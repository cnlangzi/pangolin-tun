//! The tunnel's wire protocol.
//!
//! # The shape of a tunnel
//!
//! ```text
//!                 raw HTTP/1.1 bytes (or WS frame bytes)
//!                           │
//!                           ▼
//!                  tokio::io::copy_bidirectional      ← HTTP path
//!                  hand-written half-close pump       ← WS relay
//!                           │
//!                           ▼
//!                 yamux::Stream (one per request/conn)
//!                           │
//!                           ▼
//!                 yamux::Session
//!                           │
//!                           ▼
//!              tokio::io::DuplexStream   ← yamux's "transport"
//!                           │
//!                           ▼
//!              WsBridge task: pumps bytes between
//!              the DuplexStream and the fastwebsockets
//!              WebSocket, dealing with frame boundaries.
//!                           │
//!                           ▼
//!                       tokio TCP
//! ```
//!
//! # The splice
//!
//! A tunnel stream carries a single `CONNECT <host>:<port>`
//! instruction, the tun's `OK` (or `ERR <reason>`) answer and then
//! nothing but bytes. The gateway writes the client's request bytes
//! into the stream and the tun copies them to the backend socket
//! without interpreting them — so the tun speaks no HTTP at all, and
//! SSE, WebSocket upgrades and every other protocol feature the
//! gateway owns work over the tunnel without a counterpart on the
//! tun's side.
//!
//! # Design choices
//!
//! * **yamux** is HashiCorp's compact 12-byte-header multiplexer
//!   (used by libp2p / Consul / Nomad). Its sliding-window flow
//!   control is what the old msgpack frame protocol lacked.
//! * **fastwebsockets** is a 2-4×-faster zero-copy WS parser.
//!   The `permessage-deflate` extension is built in and tuned
//!   for tun (sliding window).
//! * **Authorization: Bearer** is the auth channel. The gateway
//!   validates the token in the WebSocket upgrade callback or, over
//!   QUIC, on the control stream.
//! * **One stream per HTTP request / WS connection** — no
//!   shared-stream multiplexing, no rid correlation. Eliminates the
//!   msgpack double-parse (ngx struct → tun re-serialize).
//! * **Hop-by-hop header stripping** is the gateway's
//!   responsibility (RFC 7230 §6.1) when re-serializing the
//!   HTTP/1.1 byte stream to the backend.
//!
//! # Failure modes
//!
//! * A torn yamux stream is signalled to the peer as RST, not
//!   FIN. The peer sees EOF on the read side and surfaces the
//!   5xx to the client.
//! * A refused tunnel answers `ERR <reason>` on the stream and
//!   closes it; the gateway turns that into a 502 for the client.
//! * WS relay half-close: when one side sends EOF, the
//!   half-close pump shuts down that direction of the *other*
//!   leg and continues forwarding bytes for the still-open
//!   direction.

use std::future::Future;
use std::io::{Error, ErrorKind};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error as TunnelError, Result};

/// The tun's trust-on-first-use pin store.
pub mod pin;

/// The QUIC client and server transports.
pub mod quic;

/// The WebSocket/TCP transport.
pub mod ws;

/// Largest connection instruction the tun accepts.
pub(crate) const MAX_INSTRUCTION_LEN: usize = 4096;

/// Marker for which side of a tunnel we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRole {
    /// The gateway — accepts inbound connections and runs the yamux
    /// server.
    Server,
    /// The tun — dials outbound and runs the yamux client.
    Client,
}

/// Which transport carries a tunnel's byte streams.
///
/// Two exist: QUIC (the primary transport) and WebSocket-over-TCP
/// (the fallback for networks where UDP is blocked). The name is used
/// in the logs and in the admin UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// QUIC — one connection per tun, one bidirectional stream per
    /// request. Encrypted by default.
    Quic,
    /// WebSocket over TCP — the fallback transport.
    Tcp,
}

impl TransportKind {
    /// The stable, lower-case name used in configuration, logs and
    /// the admin UI.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::Quic => "quic",
            TransportKind::Tcp => "tcp",
        }
    }

    /// Parse the name produced by [`TransportKind::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "quic" => Some(TransportKind::Quic),
            "tcp" | "websocket" | "ws" => Some(TransportKind::Tcp),
            _ => None,
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A byte stream carried by a tunnel transport.
///
/// The tunnel is a **splice**: the gateway writes HTTP into a tunnel
/// stream and the tun copies those bytes to the backend socket
/// without interpreting them. Both transports therefore hand out plain
/// byte streams — nothing above this seam knows whether the bytes
/// travel over a QUIC bidirectional stream or a yamux stream inside a
/// WebSocket.
pub trait TunnelByteStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> TunnelByteStream for T {}

/// A boxed tunnel byte stream.
pub type TunnelStream = Box<dyn TunnelByteStream>;

/// A transport that carries a tun's byte streams.
///
/// The gateway uses [`TunnelTransport::open_stream`] to start a new
/// request stream towards a tun; the tun uses
/// [`TunnelTransport::accept_stream`] to pick up the streams the
/// gateway opened. Both directions exist on both transports (yamux and
/// QUIC are symmetric), so a single trait covers the two roles.
#[async_trait::async_trait]
pub trait TunnelTransport: Send + Sync {
    /// Open a new byte stream towards the tun.
    async fn open_stream(&self) -> Result<TunnelStream>;

    /// Accept the next inbound byte stream from the gateway. `None`
    /// means the session has ended.
    async fn accept_stream(&self) -> Option<Result<TunnelStream>>;

    /// Which transport this is — for the logs and the admin UI.
    fn kind(&self) -> TransportKind;
}

// ---------------------------------------------------------------------------
// Connection instruction
// ---------------------------------------------------------------------------

/// Encode the connection instruction the gateway writes at the start of
/// every tunnel stream:
///
/// ```text
/// CONNECT <host>:<port>\r\n
/// ```
///
/// The host is sent as a **name**, not as an address: the tun resolves
/// it in the operator's own network, so a backend that is only
/// reachable from the tun's side works. The instruction is a single
/// line, so the tun can read it before it has connected to anything.
pub fn encode_connect(host: &str, port: u16) -> Vec<u8> {
    // The instruction is a **line**: a host carrying CR, LF or NUL
    // would split it and leave a forged line in the tun's stream. The
    // backend URL is admin-controlled, so this is a defence in depth
    // rather than a reachable hole.
    if host.contains(['\r', '\n', '\0']) {
        // The host cannot be encoded safely, so the instruction is
        // deliberately malformed: the tun refuses it and the request
        // fails instead of smuggling a line.
        return b"CONNECT <invalid-host>\r\n".to_vec();
    }
    format!("CONNECT {host}:{port}\r\n").into_bytes()
}

/// Decode a `CONNECT <host>:<port>` instruction.
pub fn decode_connect(line: &[u8]) -> Result<(String, u16)> {
    let text = std::str::from_utf8(line)
        .map_err(|e| TunnelError::Protocol(format!("connect line: utf-8: {e}")))?;
    let text = text.trim_end_matches(['\r', '\n']);
    let rest = text.strip_prefix("CONNECT ").ok_or_else(|| {
        TunnelError::Protocol(format!("expected a CONNECT instruction, got {text:?}"))
    })?;
    let (host, port) = rest.rsplit_once(':').ok_or_else(|| {
        TunnelError::Protocol(format!("CONNECT instruction has no port: {text:?}"))
    })?;
    if host.is_empty() {
        return Err(TunnelError::Protocol(format!(
            "CONNECT instruction has no host: {text:?}"
        )));
    }
    let port: u16 = port.parse().map_err(|e| {
        TunnelError::Protocol(format!("CONNECT instruction has a bad port: {text:?}: {e}"))
    })?;
    // An IPv6 literal arrives bracketed (`[::1]:8080`). The brackets
    // are URL syntax, not part of the host — and `getaddrinfo` does
    // not accept them, so the tun would fail to resolve the backend.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok((host.to_string(), port))
}

/// The tun's answer to a `CONNECT` instruction: `OK\r\n`, or
/// `ERR <reason>\r\n` when the target could not be reached.
pub fn encode_connect_reply(result: std::result::Result<(), &str>) -> Vec<u8> {
    match result {
        Ok(()) => b"OK\r\n".to_vec(),
        Err(reason) => format!("ERR {reason}\r\n").into_bytes(),
    }
}

/// Decode the tun's answer to a `CONNECT` instruction.
pub fn decode_connect_reply(line: &[u8]) -> Result<std::result::Result<(), String>> {
    let text = std::str::from_utf8(line)
        .map_err(|e| TunnelError::Protocol(format!("reply: utf-8: {e}")))?;
    let text = text.trim_end_matches(['\r', '\n']);
    if text == "OK" {
        return Ok(Ok(()));
    }
    if let Some(reason) = text.strip_prefix("ERR ") {
        return Ok(Err(reason.to_string()));
    }
    Err(TunnelError::Protocol(format!(
        "unexpected CONNECT reply: {text:?}"
    )))
}

// ---------------------------------------------------------------------------
// QUIC control-stream authentication
// ---------------------------------------------------------------------------

/// Encode the QUIC control line the tun writes right after the
/// handshake:
///
/// ```text
/// AUTH <token> <name> <protocol-version>\r\n
/// ```
///
/// QUIC has no upgrade request to carry the token in, so the tun opens
/// a control stream and authenticates there. The gateway validates the
/// token against the `tun` table **before** it opens any request stream
/// on that connection.
pub fn encode_auth(token: &str, name: &str, version: u32) -> Vec<u8> {
    format!("AUTH {token} {name} {version}\r\n").into_bytes()
}

/// Decode an `AUTH <token> <name> <version>` control line.
pub fn decode_auth(line: &[u8]) -> Result<(String, String, u32)> {
    let text = std::str::from_utf8(line)
        .map_err(|e| TunnelError::Protocol(format!("auth line: utf-8: {e}")))?;
    let text = text.trim_end_matches(['\r', '\n']);
    let mut parts = text.split_whitespace();
    if parts.next() != Some("AUTH") {
        return Err(TunnelError::Protocol(format!(
            "expected an AUTH line, got {text:?}"
        )));
    }
    let token = parts
        .next()
        .ok_or_else(|| TunnelError::Protocol(format!("AUTH line has no token: {text:?}")))?;
    let name = parts
        .next()
        .ok_or_else(|| TunnelError::Protocol(format!("AUTH line has no name: {text:?}")))?;
    let version = parts
        .next()
        .ok_or_else(|| {
            TunnelError::Protocol(format!("AUTH line has no protocol version: {text:?}"))
        })?
        .parse::<u32>()
        .map_err(|e| {
            TunnelError::Protocol(format!(
                "AUTH line has a bad protocol version: {text:?}: {e}"
            ))
        })?;
    Ok((token.to_string(), name.to_string(), version))
}

/// The message both sides use when the protocol versions disagree.
///
/// It names **both** versions so the operator can tell which side is
/// behind, instead of guessing from a generic protocol error.
pub fn protocol_version_mismatch(ours: u32, theirs: u32) -> String {
    // ASCII only: the message travels in an HTTP status line (the
    // WebSocket/TCP transport refuses the upgrade with it), and a
    // status line has to stay ASCII.
    format!(
        "tunnel protocol version mismatch: this side speaks v{ours}, the peer speaks v{theirs} \
         - upgrade the tun and the gateway together"
    )
}

/// Encode the gateway's answer to an `AUTH` control line:
/// `OK <protocol-version>\r\n`, or `ERR <reason>\r\n`.
pub fn encode_auth_reply(result: std::result::Result<u32, &str>) -> Vec<u8> {
    match result {
        Ok(version) => format!("OK {version}\r\n").into_bytes(),
        Err(reason) => format!("ERR {reason}\r\n").into_bytes(),
    }
}

/// Decode the gateway's answer to an `AUTH` control line.
///
/// On success the answer carries the gateway's protocol version, so
/// the tun can refuse a gateway that speaks a different one even when
/// the tun's own line was accepted.
pub fn decode_auth_reply(line: &[u8]) -> Result<std::result::Result<u32, String>> {
    let text = std::str::from_utf8(line)
        .map_err(|e| TunnelError::Protocol(format!("auth reply: utf-8: {e}")))?;
    let text = text.trim_end_matches(['\r', '\n']);
    if let Some(rest) = text.strip_prefix("OK") {
        let version = rest
            .trim()
            .parse::<u32>()
            .map_err(|e| TunnelError::Protocol(format!("auth reply: {e}")))?;
        return Ok(Ok(version));
    }
    if let Some(reason) = text.strip_prefix("ERR ") {
        return Ok(Err(reason.to_string()));
    }
    Err(TunnelError::Protocol(format!(
        "unexpected AUTH reply: {text:?}"
    )))
}

/// Wire-format version of the tunnel protocol.
///
/// A tun and a gateway that disagree on this number speak different
/// protocols, so both sides refuse the connection with a message
/// naming **both** versions instead of failing later inside the
/// protocol with an opaque error.
///
/// The version travels in its own handshake on each transport: as an
/// extra header of the WebSocket upgrade request (TCP fallback) and in
/// the `AUTH` control line (QUIC).
pub const TUNNEL_PROTOCOL_VERSION: u32 = 2;

/// Read a single CRLF-terminated line off a byte stream.
///
/// Used for the `CONNECT` instruction, the `OK` / `ERR` reply and the
/// `AUTH` control line. The line is returned **without** its
/// terminator. `max` bounds the read so a peer that never sends a
/// newline cannot make us allocate without limit.
///
/// **The read is one byte at a time on purpose.** The gateway reads
/// the tun's `OK` reply off the *same* stream that later carries the
/// response, so a buffered read would swallow the first response
/// bytes. One byte at a time leaves the rest of the stream exactly
/// where it was.
pub async fn read_crlf_line<R>(r: &mut R, max: usize) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(64);
    let mut tmp = [0u8; 1];
    loop {
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            return Err(TunnelError::Io(Error::new(
                ErrorKind::UnexpectedEof,
                "eof before the end of the line",
            )));
        }
        if tmp[0] == b'\n' {
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
        buf.push(tmp[0]);
        if buf.len() > max {
            return Err(TunnelError::Protocol(format!(
                "line longer than {max} bytes without a terminator"
            )));
        }
    }
}

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

/// Copy bytes in both directions with **explicit half-close** handling.
///
/// When one direction reaches end-of-file, only the *write* half of
/// the other side is shut down; the other direction keeps running.
/// That is what makes a long-lived response survive the end of the
/// request: the tun shuts the backend socket's write side down when
/// the gateway's direction ends and keeps reading the response.
///
/// A plain "copy until both sides are done" would tear the whole
/// connection down as soon as one side finished — killing a response
/// whose request side had already ended.
pub async fn relay_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let mut buf_ab = vec![0u8; 16 * 1024];
    let mut buf_ba = vec![0u8; 16 * 1024];
    let mut a_done = false;
    let mut b_done = false;

    while !(a_done && b_done) {
        tokio::select! {
            r = a_read.read(&mut buf_ab), if !a_done => {
                match r {
                    Ok(0) => {
                        // The peer will not send anything more: shut
                        // down the *write* half only, so the other
                        // direction can still deliver a response.
                        let _ = b_write.shutdown().await;
                        a_done = true;
                    }
                    Ok(n) => {
                        if b_write.write_all(&buf_ab[..n]).await.is_err() {
                            // The other side is gone — tear both
                            // directions down, or the loop would
                            // spin on a failing write.
                            let _ = a_write.shutdown().await;
                            let _ = b_write.shutdown().await;
                            a_done = true;
                            b_done = true;
                        }
                    }
                    Err(_) => {
                        let _ = b_write.shutdown().await;
                        a_done = true;
                    }
                }
            }
            r = b_read.read(&mut buf_ba), if !b_done => {
                match r {
                    Ok(0) => {
                        let _ = a_write.shutdown().await;
                        b_done = true;
                    }
                    Ok(n) => {
                        if a_write.write_all(&buf_ba[..n]).await.is_err() {
                            let _ = b_write.shutdown().await;
                            let _ = a_write.shutdown().await;
                            a_done = true;
                            b_done = true;
                        }
                    }
                    Err(_) => {
                        let _ = a_write.shutdown().await;
                        b_done = true;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Serve one tunnel stream: read the CONNECT instruction, reach the
/// target, answer `OK` or `ERR`, and relay the bytes.
///
/// The dialer decides how the target is reached. The client's own
/// dialer resolves the host in the operator's network and connects
/// over TCP; a caller may dial something else.
///
/// A target that cannot be reached is answered with `ERR <reason>` and
/// the stream is closed — the gateway turns that into a 502 for the
/// client.
pub async fn serve_tunnel_stream<S, F, Fut, B>(mut stream: S, mut dial: F) -> Result<()>
where
    S: TunnelByteStream,
    F: FnMut(&str, u16) -> Fut,
    Fut: Future<Output = std::result::Result<B, TunnelError>>,
    B: TunnelByteStream,
{
    let line = read_crlf_line(&mut stream, MAX_INSTRUCTION_LEN)
        .await
        .map_err(|e| e.with_context("read the CONNECT instruction"))?;
    let (host, port) =
        decode_connect(line.as_bytes()).map_err(|e| e.with_context("bad CONNECT instruction"))?;

    let backend = match dial(&host, port).await {
        Ok(backend) => backend,
        Err(e) => {
            let reason = e.reason();
            stream
                .write_all(&encode_connect_reply(Err(&reason)))
                .await?;
            stream.flush().await?;
            return Ok(());
        }
    };

    stream.write_all(&encode_connect_reply(Ok(()))).await?;
    stream.flush().await?;

    let mut backend = backend;
    relay_bidirectional(&mut stream, &mut backend).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // Connection instruction
    // -------------------------------------------------------------------

    /// The `CONNECT` instruction is one line, so the tun can read it
    /// before it has connected to anything.
    #[test]
    fn connect_instruction_roundtrips() {
        let bytes = encode_connect("10.0.0.7", 9000);
        assert_eq!(bytes, b"CONNECT 10.0.0.7:9000\r\n");
        let (host, port) = decode_connect(&bytes).unwrap();
        assert_eq!(host, "10.0.0.7");
        assert_eq!(port, 9000);
    }

    /// The host travels as a **name**: the tun resolves it in the
    /// operator's own network, so a backend that is only reachable
    /// from the tun's side works.
    #[test]
    fn connect_instruction_carries_a_host_name() {
        let bytes = encode_connect("backend.internal", 8080);
        let (host, port) = decode_connect(&bytes).unwrap();
        assert_eq!(host, "backend.internal");
        assert_eq!(port, 8080);
    }

    /// An IPv6 literal arrives bracketed; the brackets are URL syntax
    /// and `getaddrinfo` does not accept them, so they must be
    /// stripped before the tun resolves the host.
    #[test]
    fn connect_instruction_strips_the_brackets_of_an_ipv6_literal() {
        let bytes = encode_connect("[::1]", 8080);
        let (host, port) = decode_connect(&bytes).unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    /// A host carrying a line break would split the instruction and
    /// leave a forged line in the tun's stream, so it is refused.
    #[test]
    fn connect_instruction_refuses_a_host_with_a_line_break() {
        let bytes = encode_connect("evil\r\nCONNECT other:1", 80);
        // The instruction must stay a single line.
        assert_eq!(
            bytes.iter().filter(|b| **b == b'\n').count(),
            1,
            "the instruction must not contain a second line: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(!String::from_utf8_lossy(&bytes).contains("evil"));
    }

    /// A `CONNECT` instruction without a port is refused — the tun
    /// would have nothing to dial.
    #[test]
    fn connect_instruction_without_port_is_refused() {
        let err = decode_connect(b"CONNECT 10.0.0.7\r\n").unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
    }

    /// A line that is not a `CONNECT` at all is refused too.
    #[test]
    fn connect_instruction_with_wrong_verb_is_refused() {
        let err = decode_connect(b"GET / HTTP/1.1\r\n").unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
    }

    /// The tun answers `OK` or `ERR <reason>`; both must survive the
    /// round-trip, and `ERR` must keep its reason.
    #[test]
    fn connect_reply_roundtrips() {
        assert_eq!(
            decode_connect_reply(&encode_connect_reply(Ok(()))).unwrap(),
            Ok(())
        );
        let err = decode_connect_reply(&encode_connect_reply(Err("no route to host"))).unwrap();
        assert_eq!(err, Err("no route to host".to_string()));
    }

    /// An unknown reply is a protocol error, not a silent success.
    #[test]
    fn connect_reply_with_unknown_verb_is_refused() {
        let err = decode_connect_reply(b"MAYBE\r\n").unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
    }

    // -------------------------------------------------------------------
    // QUIC control-stream authentication
    // -------------------------------------------------------------------

    /// The `AUTH` line carries the token, the tun's name and the
    /// protocol version.
    #[test]
    fn auth_line_roundtrips() {
        let bytes = encode_auth("secret-token", "office", TUNNEL_PROTOCOL_VERSION);
        let (token, name, version) = decode_auth(&bytes).unwrap();
        assert_eq!(token, "secret-token");
        assert_eq!(name, "office");
        assert_eq!(version, TUNNEL_PROTOCOL_VERSION);
    }

    /// An `AUTH` line without a protocol version is refused: the
    /// gateway could not tell whether the peer speaks the same wire
    /// format.
    #[test]
    fn auth_line_without_version_is_refused() {
        let err = decode_auth(b"AUTH token office\r\n").unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
    }

    /// The gateway's answer carries the protocol version, so a tun can
    /// refuse a gateway that speaks a different one.
    #[test]
    fn auth_reply_roundtrips() {
        let bytes = encode_auth_reply(Ok(TUNNEL_PROTOCOL_VERSION));
        assert_eq!(
            decode_auth_reply(&bytes).unwrap(),
            Ok(TUNNEL_PROTOCOL_VERSION)
        );
        let refused = decode_auth_reply(&encode_auth_reply(Err("bad token"))).unwrap();
        assert_eq!(refused, Err("bad token".to_string()));
    }

    /// An unknown answer is a protocol error, not a silent success.
    #[test]
    fn auth_reply_with_unknown_verb_is_refused() {
        let err = decode_auth_reply(b"MAYBE\r\n").unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
    }

    /// A version mismatch must name **both** versions, so the operator
    /// can tell which side is behind.
    #[test]
    fn protocol_version_mismatch_names_both_versions() {
        let msg = protocol_version_mismatch(TUNNEL_PROTOCOL_VERSION, 1);
        assert!(
            msg.contains(&format!("v{}", TUNNEL_PROTOCOL_VERSION)),
            "{msg}"
        );
        assert!(msg.contains("v1"), "{msg}");
    }

    // -------------------------------------------------------------------
    // Transport kind
    // -------------------------------------------------------------------

    /// The transport names round-trip through the parser — the tun's
    /// `transport:` selector and the log lines use the same spelling.
    #[test]
    fn transport_kind_names_roundtrip() {
        for kind in [TransportKind::Quic, TransportKind::Tcp] {
            assert_eq!(TransportKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(TransportKind::parse("QUIC"), Some(TransportKind::Quic));
        assert_eq!(TransportKind::parse(" tcp "), Some(TransportKind::Tcp));
        assert_eq!(TransportKind::parse("carrier-pigeon"), None);
    }

    // -------------------------------------------------------------------
    // The line reader
    // -------------------------------------------------------------------

    /// The line reader returns the line without its terminator.
    #[tokio::test]
    async fn the_line_reader_strips_the_terminator() {
        let (mut client, mut server) = tokio::io::duplex(64);
        server.write_all(b"CONNECT host:80\r\nrest").await.unwrap();
        assert_eq!(
            read_crlf_line(&mut client, 64).await.unwrap(),
            "CONNECT host:80"
        );
    }

    /// The line reader reads one byte at a time, so the bytes after the
    /// line stay in the stream — the gateway reads the tun's `OK` reply
    /// off the same stream that later carries the response.
    #[tokio::test]
    async fn the_line_reader_leaves_the_rest_of_the_stream() {
        let (mut client, mut server) = tokio::io::duplex(64);
        server.write_all(b"OK\r\npayload").await.unwrap();
        assert_eq!(read_crlf_line(&mut client, 64).await.unwrap(), "OK");
        let mut rest = [0u8; 7];
        client.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"payload");
    }

    /// A peer that never sends a terminator cannot make the reader
    /// allocate without limit.
    #[tokio::test]
    async fn the_line_reader_bounds_the_line() {
        let (mut client, mut server) = tokio::io::duplex(64);
        server.write_all(b"0123456789").await.unwrap();
        let err = read_crlf_line(&mut client, 4).await.unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
    }

    // -------------------------------------------------------------------
    // The relay
    // -------------------------------------------------------------------

    /// The relay must keep the response direction open after the
    /// request direction has ended — that is the whole point of the
    /// half-close handling. A backend that answers only after the
    /// request is finished has to reach the client.
    #[tokio::test]
    async fn relay_keeps_the_response_direction_open_after_the_request_ends() {
        let (mut gateway, mut backend) = tokio::io::duplex(1024);

        // The backend only answers once it has seen the end of the
        // request — i.e. after the gateway half-closed.
        let backend_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = backend.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            // Wait for the half-close (EOF on the request side).
            let mut rest = Vec::new();
            backend.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            backend.write_all(b"pong").await.unwrap();
            backend.shutdown().await.unwrap();
        });

        // The gateway writes the request and then closes its write
        // side; the response must still arrive.
        gateway.write_all(b"ping").await.unwrap();
        gateway.shutdown().await.unwrap();

        let mut seen = Vec::new();
        let mut buf = [0u8; 16];
        loop {
            let n = gateway.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n]);
        }
        assert_eq!(seen, b"pong");
        backend_task.await.unwrap();
    }

    /// The relay must stop when both directions are done — it must not
    /// spin forever after the backend closed.
    #[tokio::test]
    async fn relay_returns_when_both_directions_end() {
        let (mut a, mut a_peer) = tokio::io::duplex(64);
        let (mut b, mut b_peer) = tokio::io::duplex(64);
        let backend = tokio::spawn(async move {
            b_peer.write_all(b"hello").await.unwrap();
            b_peer.shutdown().await.unwrap();
        });
        // The gateway side closes its write half, so the relay's first
        // direction ends as well and the relay can finish.
        a_peer.shutdown().await.unwrap();
        relay_bidirectional(&mut a, &mut b).await.unwrap();
        backend.await.unwrap();
        let mut seen = Vec::new();
        a_peer.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"hello");
    }
}
