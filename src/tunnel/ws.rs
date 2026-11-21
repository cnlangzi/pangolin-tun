//! The WebSocket/TCP transport — the tunnel's fallback.
//!
//! It is the transport that existed before QUIC: a WebSocket upgrade
//! carries the tun's bearer token and the protocol version, and a
//! yamux session multiplexes the tunnel's byte streams over it.
//!
//! The transport is **unencrypted** unless the operator put TLS in
//! front of the gateway, so the client only falls back to it when the
//! QUIC attempt failed because the gateway was *unreachable* — never
//! when it failed because the gateway was *untrusted* or *refused*.

use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use fastwebsockets::{Frame, OpCode, Payload, WebSocket};
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use tokio_yamux as yamux;
use yamux::{Config as YamuxConfig, Session, StreamHandle};

use crate::error::{Error as TunnelError, Result};
use crate::tunnel::{TunnelRole, TunnelStream, TunnelTransport};

/// The `fastwebsockets` role, re-exported for callers that construct
/// WebSocket objects manually.
pub use fastwebsockets::Role as WsRole;

/// A stream of the WebSocket transport.
///
/// It wraps the upstream handle and the tunnel's liveness flag, so
/// that the end of the tunnel's **session** is reported as an error
/// instead of as a clean end-of-file.
///
/// The wrapper dereferences to the upstream handle, so `id()`,
/// `state()`, `recv_window()`, `send_window()` and `peek()` keep
/// working for a caller that holds the concrete type. `peek()` is the
/// upstream method, though: it reports the end of the byte stream the
/// way it always did, and only a read reports the session's death.
///
/// Once the session is dead, every read reports it — including a read
/// on a stream whose peer had already closed it cleanly. The upstream
/// handle cannot tell the two apart: a peer's FIN and a dropped
/// session end the stream the same way.
#[derive(Debug)]
pub struct YamuxStream {
    handle: StreamHandle,
    session_ended: Arc<AtomicBool>,
}

impl YamuxStream {
    /// Wrap a handle of a session and the flag that marks the
    /// session's end.
    fn new(handle: StreamHandle, session_ended: Arc<AtomicBool>) -> Self {
        Self {
            handle,
            session_ended,
        }
    }
}

impl std::ops::Deref for YamuxStream {
    type Target = StreamHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl std::ops::DerefMut for YamuxStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

impl AsyncRead for YamuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        // A read into a buffer with no room fills nothing by itself:
        // it says nothing about the end of the byte stream.
        let had_room = buf.remaining() > 0;
        match Pin::new(&mut this.handle).poll_read(cx, buf) {
            // A read that filled no bytes is the end of the byte
            // stream. On a dead session it is the session's death and
            // not the peer's goodbye.
            Poll::Ready(Ok(())) if had_room && buf.filled().len() == before => {
                if this.session_ended.load(Ordering::Acquire) {
                    Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "the tunnel session ended",
                    )))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for YamuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().handle).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().handle).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().handle).poll_shutdown(cx)
    }
}

/// Owns the yamux session and marks the tunnel dead when it goes.
///
/// The `Drop` body runs before the fields are dropped, so the flag is
/// set before the session's per-stream frame senders are dropped — and
/// therefore before any stream can read the end-of-file that the dead
/// session causes.
struct SessionGuard<T> {
    session: Session<T>,
    session_ended: Arc<AtomicBool>,
}

impl<T> Drop for SessionGuard<T> {
    fn drop(&mut self) {
        self.session_ended.store(true, Ordering::Release);
    }
}

// Re-exports for the manual WS handshake helpers below.
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha1::{Digest, Sha1};

/// yamux session config tuned for the HTTP-reverse-proxy
/// traffic shape Pangolin sees. Defaults are mostly fine —
/// `max_stream_count` is set explicitly so the limit is part
/// of the code we own (not a yamux-default that could change
/// between versions).
fn yamux_config() -> YamuxConfig {
    YamuxConfig {
        max_stream_count: 4096,
        ..YamuxConfig::default()
    }
}

/// A live tunnel: yamux session over a fastwebsockets
/// WebSocket, glued by a `WsBridge` task.
///
/// The session is owned by a single task (spawned by
/// [`tunnel_over_websocket`]) and is driven from there.
/// `open_stream` and `accept_stream` send commands to the
/// driver task via mpsc channels; the driver task holds
/// the `&mut Session` it needs to make those calls and
/// pumps the session's `Stream` impl to dispatch incoming
/// stream-open events back to callers waiting on
/// `accept_stream`. This avoids the `Mutex<Session>`
/// approach (where a long-poll on `next()` would block any
/// other caller from making progress) and keeps the
/// session's invariants in one place.
pub struct YamuxTunnel {
    /// Channel for sending `open_stream` requests to the
    /// driver task. Each request is a oneshot that the
    /// driver replies to with the resulting
    /// `Result<YamuxStream, Error>`.
    open_tx: mpsc::UnboundedSender<OpenRequest>,
    /// Channel for sending `accept_stream` requests. The
    /// driver task maintains a queue of pending accepts
    /// and routes incoming stream-open events to the
    /// next waiting caller.
    accept_tx: mpsc::UnboundedSender<oneshot::Sender<Result<YamuxStream>>>,
    /// Which role this endpoint plays.
    pub role: TunnelRole,
    /// Abort handle for the bridge/driver task. Held for
    /// the lifetime of the tunnel; aborting it forces
    /// both down.
    pub bridge_abort: tokio::task::AbortHandle,
    /// Notification fired by the driver when the session
    /// ends (the WebSocket EOF'd, or the session saw a
    /// go-away). Callers that need to wait for the
    /// tunnel to close `.await` this notify.
    pub session_end: Arc<tokio::sync::Notify>,
}

struct OpenRequest {
    reply: oneshot::Sender<std::result::Result<YamuxStream, yamux::Error>>,
}

impl std::fmt::Debug for YamuxTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YamuxTunnel")
            .field("role", &self.role)
            .finish()
    }
}

impl Clone for YamuxTunnel {
    fn clone(&self) -> Self {
        Self {
            open_tx: self.open_tx.clone(),
            accept_tx: self.accept_tx.clone(),
            role: self.role,
            bridge_abort: self.bridge_abort.clone(),
            session_end: self.session_end.clone(),
        }
    }
}

impl YamuxTunnel {
    /// Open a new outbound yamux stream. Each HTTP request or
    /// WS connection gets its own stream.
    pub async fn open_stream(&self) -> Result<YamuxStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_tx
            .send(OpenRequest { reply: reply_tx })
            .map_err(|_| TunnelError::Io(Error::new(ErrorKind::BrokenPipe, "tunnel closed")))?;
        match reply_rx.await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(TunnelError::Io(Error::other(format!("open_stream: {e}")))),
            Err(_) => Err(TunnelError::Io(Error::new(
                ErrorKind::BrokenPipe,
                "open_stream: no reply",
            ))),
        }
    }

    /// Accept the next inbound yamux stream. Returns
    /// `None` when the session has ended.
    pub async fn accept_stream(&self) -> Option<Result<YamuxStream>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.accept_tx.send(reply_tx).is_err() {
            return None;
        }
        match reply_rx.await {
            Ok(Ok(s)) => Some(Ok(s)),
            Ok(Err(e)) => Some(Err(TunnelError::Io(Error::other(format!(
                "accept_stream: {e}"
            ))))),
            Err(_) => None,
        }
    }
}

#[async_trait::async_trait]
impl TunnelTransport for YamuxTunnel {
    async fn open_stream(&self) -> Result<TunnelStream> {
        // `YamuxTunnel::open_stream` is the inherent method; call it
        // explicitly so the trait method does not shadow it.
        let stream = YamuxTunnel::open_stream(self).await?;
        Ok(Box::new(stream))
    }

    async fn accept_stream(&self) -> Option<Result<TunnelStream>> {
        match YamuxTunnel::accept_stream(self).await {
            Some(Ok(stream)) => Some(Ok(Box::new(stream))),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        }
    }

    fn kind(&self) -> crate::tunnel::TransportKind {
        crate::tunnel::TransportKind::Tcp
    }
}

/// Build a `YamuxTunnel` over an already-handshaken
/// `fastwebsockets::WebSocket<S>`.
///
/// The `WebSocket` is moved into a `WsBridge` task that
/// ferries bytes between the WS frame protocol and a
/// `tokio::io::DuplexStream`. Yamux operates on the duplex
/// stream, which is an in-memory byte pipe that quacks like
/// `AsyncRead + AsyncWrite + Unpin`.
pub fn tunnel_over_websocket<S>(ws: WebSocket<S>, role: TunnelRole) -> YamuxTunnel
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (yamux_side, ws_side) = tokio::io::duplex(64 * 1024);
    let session = match role {
        TunnelRole::Server => Session::new_server(yamux_side, yamux_config()),
        TunnelRole::Client => Session::new_client(yamux_side, yamux_config()),
    };
    // The flag marks the session's end. The guard sets it when the
    // session goes, and every stream the tunnel hands out carries it.
    let session_ended = Arc::new(AtomicBool::new(false));
    let guard = SessionGuard {
        session,
        session_ended,
    };
    let (open_tx, open_rx) = mpsc::unbounded_channel::<OpenRequest>();
    let (accept_tx, accept_rx) = mpsc::unbounded_channel::<oneshot::Sender<Result<YamuxStream>>>();
    let session_end = Arc::new(tokio::sync::Notify::new());
    let session_end_for_task = session_end.clone();

    // Bridge + driver in one task: the bridge ferries bytes
    // between the WebSocket and the duplex, while the
    // driver owns the `Session` exclusively and pumps its
    // `Stream` impl to dispatch accept events to callers
    // waiting on `accept_stream`. Because the session is
    // owned by a single task, there is no Mutex<Session>
    // — and no risk of a long-poll on `next()` blocking
    // other callers.
    let bridge = tokio::spawn(async move {
        // Bridge the WS and the duplex.
        let bridge_fut = ws_bridge(ws, ws_side);
        // Drive the session.
        let driver_fut = session_driver(guard, open_rx, accept_rx);
        // Whichever finishes first cancels the other.
        tokio::select! {
            _ = bridge_fut => {}
            _ = driver_fut => {}
        }
        session_end_for_task.notify_waiters();
    });
    let bridge_abort = bridge.abort_handle();
    YamuxTunnel {
        open_tx,
        accept_tx,
        role,
        bridge_abort,
        session_end,
    }
}

/// Single-task driver for a `yamux::Session` over a
/// `tokio::io::DuplexStream`. Owns the session; pumps its
/// `Stream` impl to route incoming stream-open events to
/// callers waiting on `accept_stream`; processes
/// `open_stream` requests received on `open_rx`.
async fn session_driver(
    mut guard: SessionGuard<tokio::io::DuplexStream>,
    mut open_rx: mpsc::UnboundedReceiver<OpenRequest>,
    mut accept_rx: mpsc::UnboundedReceiver<oneshot::Sender<Result<YamuxStream>>>,
) {
    use futures_util::StreamExt;
    let session_ended = guard.session_ended.clone();
    let mut pending_accepts: std::collections::VecDeque<oneshot::Sender<Result<YamuxStream>>> =
        std::collections::VecDeque::new();
    loop {
        tokio::select! {
            biased;
            // Open-stream requests from callers.
            req = open_rx.recv() => {
                let Some(req) = req else { break; };
                let result = guard.session.open_stream()
                    .map(|handle| YamuxStream::new(handle, session_ended.clone()));
                let _ = req.reply.send(result);
            }
            // Accept-stream requests from callers.
            req = accept_rx.recv() => {
                let Some(req) = req else { break; };
                pending_accepts.push_back(req);
            }
            // Incoming yamux events: an opened stream
            // (server side) is dispatched to the next
            // pending accept.
            ev = guard.session.next() => {
                match ev {
                    Some(Ok(stream)) => {
                        if let Some(reply) = pending_accepts.pop_front() {
                            let _ = reply.send(Ok(YamuxStream::new(stream, session_ended.clone())));
                        }
                        // If nobody is waiting, drop the
                        // stream — the remote opener will
                        // see a RST.
                    }
                    // `session.next()` yields Err only for **session-level**
                    // fatals — today this is exclusively the yamux
                    // keepalive timeout (ping outstanding longer than
                    // `TIMEOUT` ≈ 30s; triggered by `kill -9`, OOM,
                    // container restart, network partition, etc.) and
                    // any transport-level I/O error on the underlying
                    // duplex (yamux surfaces transport errors through
                    // the same path). yamux's `Stream` impl does not
                    // surface per-stream errors here — those are
                    // observed by the `StreamHandle`'s own read/write
                    // methods, not by `Session::poll_next`.
                    //
                    // This Err must therefore terminate the driver
                    // loop: forwarding it to a single pending
                    // acceptor and continuing leaves
                    // `session.is_dead()` false, so the surrounding
                    // bridge task never wakes up `session_end` and the
                    // `mark_tun_offline` call site never runs; the DB
                    // row stays `online=1` until the OS TCP timeout
                    // (minutes to hours) finally catches the half-open
                    // connection. Breaking out lets the surrounding
                    // `tokio::select!` reach the
                    // `session_end_for_task.notify_waiters()` line so
                    // the existing call site fires.
                    //
                    // Pending acceptors are drained with EOF below the
                    // loop, so they don't hang.
                    Some(Err(e)) => {
                        // Surface the error at debug so operators can
                        // distinguish a clean peer disconnect (the
                        // `None` arm above) from a real session-level
                        // fatal — keepalive timeout (the half-open
                        // case), transport I/O error, or go-away.
                        // Without this, every session end looks
                        // identical in the logs.
                        debug!("tunnel: session ended with error: {e}");
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    // Session ended: drain pending acceptors with an EOF
    // error so they don't hang.
    while let Some(reply) = pending_accepts.pop_front() {
        let _ = reply.send(Err(TunnelError::Io(Error::new(
            ErrorKind::UnexpectedEof,
            "yamux session ended",
        ))));
    }
}

// ---------------------------------------------------------------------------
// WsBridge: ferries bytes between a WebSocket and a DuplexStream.
// ---------------------------------------------------------------------------

/// Bridge task: pump bytes from a `WebSocket` to a
/// `DuplexStream` (in both directions).
///
/// Each WebSocket Binary frame is a chunk of bytes on the
/// duplex stream; the receiving side reads them
/// transparently. The bridge is symmetric: the *y* end of
/// the duplex is owned by yamux; the *s* end is owned by
/// this task. On EOF from either side, the task ends.
async fn ws_bridge<S>(mut ws: WebSocket<S>, mut s: tokio::io::DuplexStream)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = vec![0u8; 16 * 1024];
    // We need two pump directions in one task. We use
    // tokio::select! on (read WS frame, read from duplex).
    // When the duplex's reader returns EOF, the bridge
    // sends a Close frame on the WS and ends. When the
    // WS read returns None (Close), the bridge shuts
    // down the duplex writer and ends.
    let mut ws_closed = false;
    let mut duplex_closed = false;
    loop {
        if ws_closed && duplex_closed {
            return;
        }
        tokio::select! {
            // duplex → WS
            res = s.read(&mut buffer), if !duplex_closed => {
                match res {
                    Ok(0) => {
                        // yamux closed its end → send Close frame
                        let close_frame = Frame::new(true, OpCode::Close, None, Payload::Owned(Vec::new()));
                        if ws.write_frame(close_frame).await.is_err() {
                            return;
                        }
                        duplex_closed = true;
                    }
                    Ok(n) => {
                        let frame = Frame::new(true, OpCode::Binary, None, Payload::Borrowed(&buffer[..n]));
                        if ws.write_frame(frame).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = ws.write_frame(Frame::new(true, OpCode::Close, None, Payload::Owned(Vec::new()))).await;
                        return;
                    }
                }
            }
            // WS → duplex
            res = ws.read_frame(), if !ws_closed => {
                match res {
                    Ok(frame) => match frame.opcode {
                        OpCode::Binary => {
                            let payload = frame.payload.to_vec();
                            if s.write_all(&payload).await.is_err() {
                                return;
                            }
                        }
                        OpCode::Close => {
                            let _ = s.shutdown().await;
                            ws_closed = true;
                        }
                        OpCode::Ping | OpCode::Pong => {
                            // auto-pong handled by fastwebsockets
                        }
                        other => {
                            debug!("ws bridge: ignoring opcode {:?}", other);
                        }
                    },
                    Err(_) => {
                        let _ = s.shutdown().await;
                        return;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Manual WebSocket handshake helpers (server + client)
// ---------------------------------------------------------------------------

const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Generate a random 16-byte base64-encoded
/// `Sec-WebSocket-Key` value (RFC 6455 §1.3).
pub fn generate_ws_key() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    BASE64.encode(bytes)
}

/// Compute the `Sec-WebSocket-Accept` value for the given
/// `Sec-WebSocket-Key` (RFC 6455 §1.3).
pub fn compute_ws_accept(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.trim().as_bytes());
    sha.update(WS_MAGIC.as_bytes());
    BASE64.encode(sha.finalize())
}

/// A parsed minimal view of a WebSocket upgrade request.
///
/// The `Debug` impl redacts the `Authorization` header: the struct
/// carries the tun's bearer token, and a `{:?}` dump would put the
/// credential into the log.
#[derive(Clone)]
pub struct WsUpgradeRequest {
    /// The request's method — `GET` for an upgrade.
    pub method: String,
    /// The request's target — the tun's path with its query.
    pub target: String,
    /// The HTTP version of the request line.
    pub version: String,
    /// The `Authorization` header, if the request carried one.
    pub authorization: Option<String>,
    /// The `Sec-WebSocket-Key` header, if the request carried one.
    pub sec_websocket_key: Option<String>,
    /// Every header of the request, in order. The tunnel protocol
    /// version travels in [`TUNNEL_VERSION_HEADER`]; the named fields
    /// above are the ones the handshake itself needs.
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for WsUpgradeRequest {
    /// Redacts the `Authorization` header.
    ///
    /// The struct carries the tun's bearer token; the derived `Debug`
    /// would put it into every log line that dumps the request.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |name: &str| name.eq_ignore_ascii_case("authorization");
        f.debug_struct("WsUpgradeRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("version", &self.version)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field("sec_websocket_key", &self.sec_websocket_key)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(k, v)| {
                        if redact(k) {
                            (k, "<redacted>".to_string())
                        } else {
                            (k, v.clone())
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The header the WebSocket/TCP transport carries the tunnel protocol
/// version in.
///
/// The WebSocket upgrade request is the only handshake the TCP
/// fallback has, so the version rides along as an extra header. A
/// tun that omits it is a tun that predates the splice — the gateway
/// refuses the upgrade rather than speaking two protocols at once.
pub const TUNNEL_VERSION_HEADER: &str = "X-Pangolin-Tunnel-Version";

/// Read a single WebSocket upgrade request off an arbitrary
/// `AsyncRead` stream.
pub async fn read_ws_upgrade_request<R>(r: &mut R) -> Result<WsUpgradeRequest>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    loop {
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            return Err(TunnelError::Io(Error::new(
                ErrorKind::UnexpectedEof,
                "eof in upgrade headers",
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = find_header_end(&buf) {
            let head = std::str::from_utf8(&buf[..idx])
                .map_err(|e| TunnelError::Protocol(format!("utf-8: {e}")))?;
            return Ok(parse_ws_upgrade_request(head));
        }
        if buf.len() > 16 * 1024 {
            return Err(TunnelError::Protocol(
                "upgrade headers >16 KiB without CRLFCRLF".to_string(),
            ));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_ws_upgrade_request(head: &str) -> WsUpgradeRequest {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    let mut authorization = None;
    let mut sec_websocket_key = None;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k_lc = k.trim().to_ascii_lowercase();
            let v = v.trim().to_string();
            if k_lc == "authorization" {
                authorization = Some(v.clone());
            } else if k_lc == "sec-websocket-key" {
                sec_websocket_key = Some(v.clone());
            }
            headers.push((k.trim().to_string(), v));
        }
    }
    WsUpgradeRequest {
        method,
        target,
        version,
        authorization,
        sec_websocket_key,
        headers,
    }
}

/// Extract the `Bearer <token>` from an `Authorization: …`
/// header value.
pub fn bearer_token(authorization: Option<&str>) -> Option<String> {
    let v = authorization?;
    let mut parts = v.splitn(2, ' ');
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = parts.next()?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Write a `101 Switching Protocols` response to the stream.
pub async fn write_ws_accept_response<W>(w: &mut W, key: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let accept = compute_ws_accept(key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept
    );
    w.write_all(resp.as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

/// Write an HTTP/1.1 error response and shut the stream down.
pub async fn write_http_error<W>(w: &mut W, status: u16, reason: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = format!("{status} {reason}\n");
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    w.write_all(resp.as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

/// Build a WebSocket upgrade request bytes for the client
/// side. Returns the full HTTP/1.1 request text and the
/// `Sec-WebSocket-Key` it carries. The caller writes it to the stream
/// and then awaits the 101 response.
///
/// `extra_headers` are appended after the built-in ones — the tun's
/// registration handshake carries the protocol version that way.
///
/// Header values are sanitized: CR / LF are stripped so a value
/// that reached us from the wire can never inject a header into the
/// backend's request.
pub fn build_ws_upgrade_request(
    path: &str,
    host: &str,
    token: &str,
    extra_headers: &[(String, String)],
) -> (Vec<u8>, String) {
    let key = generate_ws_key();
    let mut req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Authorization: Bearer {token}\r\n"
    );
    for (name, value) in extra_headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(&sanitize_header_value(value));
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    (req.into_bytes(), key)
}

/// Strip CR / LF from a header value so it cannot terminate the
/// header line it is written into.
fn sanitize_header_value(value: &str) -> String {
    value.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// Read the 101 response off the stream and validate the
/// `Sec-WebSocket-Accept` value matches what we sent.
pub async fn read_ws_accept_response<R>(r: &mut R, expected_key: &str) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    // **The read is one byte at a time on purpose.** The bytes that
    // follow the 101 response are the first frames of the WebSocket
    // session, so a buffered read that stopped at the header end
    // would have to hand the rest back to the caller — and a read
    // that simply swallowed them would destroy the first frame of
    // the session. One byte at a time leaves the stream exactly
    // where the response ended.
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 1];
    loop {
        let n = r.read(&mut tmp).await?;
        if n == 0 {
            return Err(TunnelError::Io(Error::new(
                ErrorKind::UnexpectedEof,
                "eof in 101 response",
            )));
        }
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            // The terminator is not part of the head.
            let head = std::str::from_utf8(&buf[..buf.len() - 4])
                .map_err(|e| TunnelError::Protocol(format!("utf-8: {e}")))?;
            let status_line = head.lines().next().unwrap_or("");
            if !status_line.contains(" 101 ") {
                return Err(TunnelError::Protocol(format!(
                    "expected 101 Switching Protocols, got: {status_line}"
                )));
            }
            let expected = compute_ws_accept(expected_key);
            if !head.lines().any(|l| {
                l.split_once(':')
                    .map(|(k, v)| {
                        k.trim().eq_ignore_ascii_case("sec-websocket-accept")
                            && v.trim() == expected
                    })
                    .unwrap_or(false)
            }) {
                return Err(TunnelError::Protocol(
                    "Sec-WebSocket-Accept mismatch".to_string(),
                ));
            }
            return Ok(());
        }
        if buf.len() > 16 * 1024 {
            return Err(TunnelError::Protocol(
                "101 response headers >16 KiB".to_string(),
            ));
        }
    }
}

/// Wrap an `AsyncRead+AsyncWrite` stream as a
/// `fastwebsockets::WebSocket<S>` after the WS upgrade has
/// already been performed manually. Used by both the tun
/// client and the gateway after a successful handshake.
pub fn wrap_websocket<S>(stream: S, role: WsRole) -> WebSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    WebSocket::after_handshake(stream, role)
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::time::Duration;

    use super::*;

    /// Two tunnels connected to each other over a WebSocket.
    fn tunnel_pair() -> (YamuxTunnel, YamuxTunnel) {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        (
            tunnel_over_websocket(
                wrap_websocket(client_side, WsRole::Client),
                TunnelRole::Client,
            ),
            tunnel_over_websocket(
                wrap_websocket(server_side, WsRole::Server),
                TunnelRole::Server,
            ),
        )
    }

    /// Open a stream on the client and accept it on the server.
    ///
    /// The tunnel's driver drops a stream that arrives while nobody
    /// waits for it, so the accept request has to be on its way
    /// before the client opens the stream.
    async fn open_and_accept(
        client: &YamuxTunnel,
        server: &YamuxTunnel,
    ) -> (YamuxStream, YamuxStream) {
        let mut accept = Box::pin(server.accept_stream());
        // Poll the acceptor once: the request is sent, and no stream
        // can have arrived yet.
        let pending = poll_fn(|cx| Poll::Ready(accept.as_mut().poll(cx))).await;
        assert!(pending.is_pending(), "no stream has been opened yet");

        let client_stream = client.open_stream().await.unwrap();
        let server_stream = accept.await.unwrap().unwrap();
        (client_stream, server_stream)
    }

    /// The `Sec-WebSocket-Accept` value is the RFC 6455 §1.3
    /// derivation — a gateway and a tun that compute it differently
    /// would never complete the handshake.
    #[test]
    fn the_accept_value_follows_rfc_6455() {
        assert_eq!(
            compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// The accept value ignores the padding around the key.
    #[test]
    fn the_accept_value_ignores_the_padding_around_the_key() {
        assert_eq!(
            compute_ws_accept("  dGhlIHNhbXBsZSBub25jZQ==  "),
            compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ==")
        );
    }

    /// The key is random, so two upgrades never carry the same one.
    #[test]
    fn the_key_is_random() {
        assert_ne!(generate_ws_key(), generate_ws_key());
    }

    /// The bearer token is the tun's credential; the header's scheme
    /// is case-insensitive and the token itself is kept as it is.
    #[test]
    fn the_bearer_token_is_extracted() {
        assert_eq!(
            bearer_token(Some("Bearer secret-token")),
            Some("secret-token".to_string())
        );
        assert_eq!(
            bearer_token(Some("bearer secret-token")),
            Some("secret-token".to_string())
        );
    }

    /// A header that is not a bearer token yields no token — the
    /// gateway must not accept another scheme.
    #[test]
    fn a_non_bearer_header_yields_no_token() {
        assert_eq!(bearer_token(Some("Basic dXNlcjpwYXNz")), None);
        assert_eq!(bearer_token(Some("Bearer   ")), None);
        assert_eq!(bearer_token(None), None);
    }

    /// The upgrade request is parsed into its parts, and the protocol
    /// version header is one of them.
    #[tokio::test]
    async fn the_upgrade_request_is_parsed() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        server
            .write_all(
                b"GET /tunnel?name=office HTTP/1.1\r\n\
                  Host: gateway.example:8080\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Authorization: Bearer secret-token\r\n\
                  X-Pangolin-Tunnel-Version: 2\r\n\
                  \r\n",
            )
            .await
            .unwrap();
        let request = read_ws_upgrade_request(&mut client).await.unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/tunnel?name=office");
        assert_eq!(
            request.sec_websocket_key.as_deref(),
            Some("dGhlIHNhbXBsZSBub25jZQ==")
        );
        assert_eq!(
            request.authorization.as_deref(),
            Some("Bearer secret-token")
        );
        let version = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(TUNNEL_VERSION_HEADER))
            .map(|(_, v)| v.as_str());
        assert_eq!(version, Some("2"));
    }

    /// The `Debug` impl redacts the bearer token — a log line that
    /// dumps the request must not leak the credential.
    #[test]
    fn the_debug_impl_redacts_the_authorization_header() {
        let request = WsUpgradeRequest {
            method: "GET".into(),
            target: "/tunnel".into(),
            version: "HTTP/1.1".into(),
            authorization: Some("Bearer secret-token".into()),
            sec_websocket_key: None,
            headers: vec![("Authorization".into(), "Bearer secret-token".into())],
        };
        let dumped = format!("{request:?}");
        assert!(!dumped.contains("secret-token"), "{dumped}");
        assert!(dumped.contains("<redacted>"), "{dumped}");
    }

    /// The bytes that follow the 101 response are the first frames
    /// of the session: the reader must not swallow them.
    #[tokio::test]
    async fn the_accept_response_leaves_the_rest_of_the_stream() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let key = generate_ws_key();
        let mut response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            compute_ws_accept(&key)
        )
        .into_bytes();
        response.extend_from_slice(b"the first frame");
        server.write_all(&response).await.unwrap();

        read_ws_accept_response(&mut client, &key).await.unwrap();

        let mut rest = [0u8; 15];
        client.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"the first frame");
    }

    /// The upgrade request carries the protocol version as an extra
    /// header — the only handshake the fallback transport has.
    #[test]
    fn the_upgrade_request_carries_the_protocol_version() {
        let extra = vec![(TUNNEL_VERSION_HEADER.to_string(), "2".to_string())];
        let (bytes, key) =
            build_ws_upgrade_request("/tunnel?name=office", "gw:8080", "tok", &extra);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("X-Pangolin-Tunnel-Version: 2\r\n"), "{text}");
        assert!(text.contains("Authorization: Bearer tok\r\n"), "{text}");
        assert!(
            text.contains(&format!("Sec-WebSocket-Key: {key}\r\n")),
            "{text}"
        );
    }

    /// A header value that reached the crate from the wire cannot
    /// inject a header into the request: the CR and the LF are
    /// stripped, so the value cannot terminate its own line and start
    /// a new header.
    #[test]
    fn the_upgrade_request_sanitizes_the_header_values() {
        let extra = vec![("X-Test".to_string(), "a\r\nX-Injected: yes".to_string())];
        let (bytes, _) = build_ws_upgrade_request("/tunnel", "gw:8080", "tok", &extra);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("X-Test: aX-Injected: yes\r\n"), "{text}");
        assert!(
            !text.lines().any(|line| line.starts_with("X-Injected")),
            "the value must not become a header of its own: {text}"
        );
    }

    /// A session that dies while a stream is open reports its death on
    /// that stream: the read is an error, not a clean end-of-file.
    ///
    /// A clean end-of-file says "the peer finished sending"; a dead
    /// session says "the bytes that were still to come will never
    /// come". A consumer that cannot tell the two apart relays a
    /// truncated response as if it were a whole one.
    #[tokio::test]
    async fn a_dead_session_reports_its_death_on_the_open_stream() {
        let (client, server) = tunnel_pair();
        let (_client_stream, mut server_stream) = open_and_accept(&client, &server).await;

        // The session dies: the bridge task is dropped, and with it
        // the yamux session.
        server.bridge_abort.abort();

        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut buf))
            .await
            .expect("the read must not hang")
            .expect_err("a dead session must not read as an end-of-file");
        assert_eq!(err.kind(), ErrorKind::NotConnected);
        assert_eq!(err.to_string(), "the tunnel session ended");
    }

    /// A read into a buffer with no room fills nothing by itself: it
    /// says nothing about the end of the byte stream, and it must not
    /// report the session's death either.
    #[tokio::test]
    async fn an_empty_read_is_not_the_death() {
        let (client, server) = tunnel_pair();
        let (_client_stream, mut server_stream) = open_and_accept(&client, &server).await;
        server.bridge_abort.abort();
        let mut empty: [u8; 0] = [];
        let n = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut empty))
            .await
            .expect("the read must not hang")
            .expect("an empty read must not be the death");
        assert_eq!(n, 0);
    }

    /// A peer that closes its half of the stream sends a FIN: the read
    /// is still a clean end-of-file, and the new check does not fire.
    #[tokio::test]
    async fn a_cleanly_closed_stream_still_reads_an_end_of_file() {
        let (client, server) = tunnel_pair();
        let (mut client_stream, mut server_stream) = open_and_accept(&client, &server).await;

        // The gateway closes its half of the stream.
        server_stream.shutdown().await.unwrap();

        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), client_stream.read(&mut buf))
            .await
            .expect("the read must not hang")
            .expect("a clean close must not be an error");
        assert_eq!(n, 0, "the peer that finished sending reads as zero bytes");
    }

    /// Data that arrived before the session died is delivered first;
    /// the read after it reports the death.
    #[tokio::test]
    async fn the_data_that_arrived_before_the_death_is_delivered_first() {
        let (client, server) = tunnel_pair();
        let (mut client_stream, mut server_stream) = open_and_accept(&client, &server).await;

        client_stream.write_all(b"hello").await.unwrap();
        client_stream.flush().await.unwrap();

        // Wait until the bytes are in the stream's buffer, so the
        // death cannot overtake them.
        let mut peeked = [0u8; 5];
        let buffered =
            tokio::time::timeout(Duration::from_secs(5), server_stream.peek(&mut peeked))
                .await
                .expect("the data must arrive")
                .expect("the peek must not fail");
        assert_eq!(buffered, 5);

        server.bridge_abort.abort();

        let mut buf = [0u8; 5];
        let n = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut buf))
            .await
            .expect("the read must not hang")
            .expect("the data must be delivered");
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        let err = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut buf))
            .await
            .expect("the read must not hang")
            .expect_err("the dead session must not read as an end-of-file");
        assert_eq!(err.kind(), ErrorKind::NotConnected);
    }
}
