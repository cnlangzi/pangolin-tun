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

/// Largest protocol line the tunnel accepts.
///
/// The protocol fixes the length of every line it puts on the wire:
/// the `CONNECT` instruction, the `OK` / `ERR` reply and the `AUTH`
/// control line are all at most this long.
///
/// The reader applies the limit to the bytes it accumulates before
/// the LF, so the CR of a CRLF terminator counts against it.
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
/// (the fallback for networks where UDP is blocked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// QUIC — one connection per tun, one bidirectional stream per
    /// request. Encrypted by default.
    Quic,
    /// WebSocket over TCP — the fallback transport.
    Tcp,
}

impl TransportKind {
    /// The stable, lower-case name of the transport — the spelling the
    /// log lines and the admin UI use.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::Quic => "quic",
            TransportKind::Tcp => "tcp",
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
///
/// A stream is moved into the one task that serves it, so `Send` is
/// what the crate needs; `Sync` would constrain every transport's
/// stream for nothing.
pub trait TunnelByteStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelByteStream for T {}

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
///
/// The reason is one line: CR and LF are replaced with a space, so a
/// reason can never smuggle a second line into the gateway's stream.
/// It is bounded as well — the reply is a protocol line, and a reason
/// that quotes the instruction it is about would push it past the
/// line limit.
pub fn encode_connect_reply(result: std::result::Result<(), &str>) -> Vec<u8> {
    match result {
        Ok(()) => b"OK\r\n".to_vec(),
        Err(reason) => {
            let reason = bounded_reason(reason);
            format!("ERR {reason}\r\n").into_bytes()
        }
    }
}

/// The reason of an `ERR` reply, on one line and within the line
/// limit.
///
/// The reason can quote the instruction it is about — and the
/// instruction is a protocol line itself, so the reply has to be
/// bounded: the peer's line reader would refuse a longer one.
fn bounded_reason(reason: &str) -> String {
    // The "ERR " prefix and the CRLF terminator count against the
    // limit, and the ellipsis that marks a cut reason takes three
    // more.
    const LIMIT: usize = MAX_INSTRUCTION_LEN - "ERR ".len() - 2;
    const MARKER: &str = "...";
    let reason = reason.replace(['\r', '\n'], " ");
    if reason.len() <= LIMIT {
        return reason;
    }
    let mut end = LIMIT - MARKER.len();
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{MARKER}", &reason[..end])
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
/// terminator. The crate enforces the line limit itself, so a peer
/// that never sends a newline cannot make us allocate without limit.
///
/// **The read is one byte at a time on purpose.** The gateway reads
/// the tun's `OK` reply off the *same* stream that later carries the
/// response, so a buffered read would swallow the first response
/// bytes. One byte at a time leaves the rest of the stream exactly
/// where it was.
pub async fn read_crlf_line<R>(r: &mut R) -> Result<String>
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
        if buf.len() > MAX_INSTRUCTION_LEN {
            return Err(TunnelError::Protocol(format!(
                "line longer than {MAX_INSTRUCTION_LEN} bytes without a terminator"
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
///
/// The first error either side reports ends the relay: both
/// directions are torn down and the error is returned. An error is
/// not an end-of-file — it says that the bytes that were still to
/// come will never come, and a caller that cannot tell the two apart
/// reads a failed tunnel as a finished one.
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
                        if let Err(e) = b_write.write_all(&buf_ab[..n]).await {
                            // The other side is gone — tear both
                            // directions down, or the loop would
                            // spin on a failing write.
                            let _ = a_write.shutdown().await;
                            let _ = b_write.shutdown().await;
                            return Err(TunnelError::Io(e));
                        }
                    }
                    Err(e) => {
                        // The read failed: the bytes that were still to
                        // come will never come, so both directions go
                        // down and the failure is reported.
                        let _ = a_write.shutdown().await;
                        let _ = b_write.shutdown().await;
                        return Err(TunnelError::Io(e));
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
                        if let Err(e) = a_write.write_all(&buf_ba[..n]).await {
                            let _ = b_write.shutdown().await;
                            let _ = a_write.shutdown().await;
                            return Err(TunnelError::Io(e));
                        }
                    }
                    Err(e) => {
                        // The read failed: the bytes that were still to
                        // come will never come, so both directions go
                        // down and the failure is reported.
                        let _ = b_write.shutdown().await;
                        let _ = a_write.shutdown().await;
                        return Err(TunnelError::Io(e));
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
/// client. So is an instruction that cannot be decoded: the line was
/// read, so the reason can be answered with it.
pub async fn serve_tunnel_stream<S, F, Fut, B>(mut stream: S, mut dial: F) -> Result<()>
where
    S: TunnelByteStream,
    F: FnMut(&str, u16) -> Fut,
    Fut: Future<Output = std::result::Result<B, TunnelError>>,
    B: TunnelByteStream,
{
    let line = read_crlf_line(&mut stream)
        .await
        .map_err(|e| e.with_context("read the CONNECT instruction"))?;
    let (host, port) = match decode_connect(line.as_bytes()) {
        Ok(target) => target,
        Err(e) => {
            // The instruction is malformed: the target is not even
            // known.
            refuse(&mut stream, &e.reason()).await?;
            return Ok(());
        }
    };

    let backend = match dial(&host, port).await {
        Ok(backend) => backend,
        Err(e) => {
            refuse(&mut stream, &e.reason()).await?;
            return Ok(());
        }
    };

    stream.write_all(&encode_connect_reply(Ok(()))).await?;
    stream.flush().await?;

    let mut backend = backend;
    relay_bidirectional(&mut stream, &mut backend).await
}

/// Answer a request with `ERR <reason>`.
///
/// The reason is one line and within the line limit, so the answer
/// cannot smuggle a second line into the peer's stream — and the
/// peer's line reader accepts it.
async fn refuse<S: TunnelByteStream>(stream: &mut S, reason: &str) -> Result<()> {
    stream.write_all(&encode_connect_reply(Err(reason))).await?;
    stream.flush().await?;
    Ok(())
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

    /// The reason of an `ERR` reply is one line: a reason carrying a
    /// line break would smuggle a second line into the gateway's
    /// stream.
    #[test]
    fn the_err_reason_stays_on_one_line() {
        let bytes = encode_connect_reply(Err("no route\r\nCONNECT other:1"));
        assert_eq!(
            bytes.iter().filter(|b| **b == b'\n').count(),
            1,
            "the reply must not contain a second line: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.lines().any(|line| line.starts_with("CONNECT")),
            "the reason must not become a line of its own: {text}"
        );
    }

    /// The reply is a protocol line: a reason that quotes the
    /// instruction it is about must not push it past the line limit,
    /// or the peer's line reader would refuse it.
    #[test]
    fn the_err_reply_stays_within_the_line_limit() {
        let reason = "x".repeat(MAX_INSTRUCTION_LEN * 2);
        let bytes = encode_connect_reply(Err(&reason));
        assert!(
            bytes.len() <= MAX_INSTRUCTION_LEN,
            "the reply must fit the line limit: {} bytes",
            bytes.len()
        );
        assert_eq!(
            bytes.iter().filter(|b| **b == b'\n').count(),
            1,
            "the reply must not contain a second line"
        );
    }

    /// An unknown reply is a protocol error, not a silent success.
    #[test]
    fn connect_reply_with_unknown_verb_is_refused() {
        let err = decode_connect_reply(b"MAYBE\r\n").unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
    }

    /// A malformed CONNECT instruction is refused with a reason: the
    /// gateway turns the `ERR` into a 502, and the reason names what
    /// was wrong with the instruction.
    #[tokio::test]
    async fn a_malformed_connect_instruction_is_answered_with_err() {
        let (mut gateway, tunnel) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            let dial =
                |_host: &str, _port: u16| async { Ok::<_, TunnelError>(tokio::io::duplex(8).0) };
            serve_tunnel_stream(tunnel, dial).await
        });

        gateway
            .write_all(b"CONNECT <invalid-host>\r\n")
            .await
            .unwrap();
        gateway.flush().await.unwrap();

        let reply = read_crlf_line(&mut gateway).await.unwrap();
        assert!(reply.starts_with("ERR "), "the tun must refuse it: {reply}");
        // The reply is the last thing on the stream: the reason
        // cannot have smuggled a second line behind it.
        let mut rest = Vec::new();
        gateway.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "nothing may follow the reply: {rest:?}");
        relay.await.unwrap().unwrap();
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

    /// The transport names are the crate's output vocabulary — the log
    /// lines and the admin UI print them.
    #[test]
    fn the_transport_kind_names_are_stable() {
        assert_eq!(TransportKind::Quic.as_str(), "quic");
        assert_eq!(TransportKind::Tcp.as_str(), "tcp");
        assert_eq!(TransportKind::Quic.to_string(), "quic");
        assert_eq!(TransportKind::Tcp.to_string(), "tcp");
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
            read_crlf_line(&mut client).await.unwrap(),
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
        assert_eq!(read_crlf_line(&mut client).await.unwrap(), "OK");
        let mut rest = [0u8; 7];
        client.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"payload");
    }

    /// A peer that never sends a terminator cannot make the reader
    /// allocate without limit: the protocol's line limit is the
    /// crate's own.
    #[tokio::test]
    async fn the_line_reader_bounds_the_line() {
        let (mut client, mut server) = tokio::io::duplex(MAX_INSTRUCTION_LEN + 1);
        let too_long = vec![b'x'; MAX_INSTRUCTION_LEN + 1];
        server.write_all(&too_long).await.unwrap();
        let err = read_crlf_line(&mut client).await.unwrap_err();
        assert!(matches!(err, TunnelError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("4096"), "{err}");
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

    /// A side that fails ends the relay, and the error reaches the
    /// caller. A relay that swallows it reads a dead tunnel as a
    /// finished one — and the truncated response it relays looks like
    /// a whole one.
    #[tokio::test]
    async fn the_relay_reports_a_failing_side() {
        let (mut other, _other_peer) = tokio::io::duplex(64);
        let mut failing = FailingStream;
        let err = relay_bidirectional(&mut failing, &mut other)
            .await
            .expect_err("a failing side must not be swallowed");
        match err {
            TunnelError::Io(e) => assert_eq!(e.kind(), ErrorKind::NotConnected, "{e}"),
            other => panic!("the relay must report the I/O failure: {other:?}"),
        }
    }

    /// A write that fails ends the relay too: the bytes the other side
    /// sent cannot be handed over, and the failure is reported.
    #[tokio::test]
    async fn the_relay_reports_a_failing_write() {
        let (mut other, mut other_peer) = tokio::io::duplex(64);
        other_peer.write_all(b"hello").await.unwrap();
        let mut failing = FailingWriteStream;
        let err = relay_bidirectional(&mut other, &mut failing)
            .await
            .expect_err("a failing write must not be swallowed");
        match err {
            TunnelError::Io(e) => assert_eq!(e.kind(), ErrorKind::BrokenPipe, "{e}"),
            other => panic!("the relay must report the I/O failure: {other:?}"),
        }
    }

    /// A stream whose read always fails — the tunnel's session died
    /// under it.
    struct FailingStream;

    impl AsyncRead for FailingStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(Error::new(
                ErrorKind::NotConnected,
                "the tunnel session ended",
            )))
        }
    }

    impl AsyncWrite for FailingStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A stream that takes every byte and hands none of them on: the
    /// other side is gone.
    struct FailingWriteStream;

    impl AsyncRead for FailingWriteStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl AsyncWrite for FailingWriteStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "the other side is gone",
            )))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
