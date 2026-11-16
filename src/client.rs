//! The tunnel client — a **byte relay**.
//!
//! ## Architecture
//!
//! The gateway's proxy stack writes the client's request bytes into a
//! tunnel stream and reads the backend's bytes out of it. The client's
//! job is therefore tiny:
//!
//! 1. read the `CONNECT <host>:<port>` instruction;
//! 2. resolve the host **in the operator's own network** and dial it;
//! 3. answer `OK` (or `ERR <reason>`);
//! 4. copy bytes in both directions until both sides are done.
//!
//! The client does not speak HTTP. It never parses a request, never
//! builds one and never buffers a response — which is why SSE,
//! WebSocket upgrades and any other protocol feature the gateway
//! owns work over the tunnel without a counterpart on this side.
//!
//! ## Transports
//!
//! Two transports implement the same interface
//! ([`crate::tunnel::TunnelTransport`]):
//!
//! * **QUIC** (primary) — one connection per tun, one bidirectional
//!   stream per request. Encrypted by default. The client authenticates
//!   on a control stream right after the handshake.
//! * **WebSocket over TCP** (fallback) — the transport used before
//!   QUIC existed, kept for networks where UDP is blocked.
//!
//! The transport is chosen **once per session**. At the start of a
//! session the client attempts QUIC with a five-second handshake
//! timeout; on failure it falls back to the WebSocket/TCP transport
//! and stays on it for the rest of the session. It records the time of
//! the failure and does not probe QUIC again for ten minutes, so a
//! network that blocks UDP does not pay the timeout on every
//! reconnect.
//!
//! A failure that is **not** "the gateway could not be reached" never
//! falls back: the fallback is unencrypted, so it would hand the
//! bearer token to whoever is presenting the wrong certificate, or
//! carry a token the gateway already refused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

use crate::error::{Error as TunnelError, Result};
use crate::settings::{TransportSelector, TunSettings};
use crate::tunnel::pin::PinStore;
use crate::tunnel::quic::{QuicClientTransport, QuicConnectError, QuicHandshake};
use crate::tunnel::ws::{
    TUNNEL_VERSION_HEADER, WsRole, build_ws_upgrade_request, read_ws_accept_response,
    tunnel_over_websocket,
};
use crate::tunnel::{
    MAX_INSTRUCTION_LEN, TUNNEL_PROTOCOL_VERSION, TransportKind, TunnelRole, TunnelTransport,
    decode_auth_reply, encode_auth, protocol_version_mismatch, read_crlf_line, serve_tunnel_stream,
};

/// How long the client waits for the QUIC handshake before it gives up
/// and falls back to the WebSocket/TCP transport.
///
/// A network that silently drops UDP (no ICMP) never produces an
/// error — the timeout is what saves the connection, so it has to be
/// short enough to keep the fallback responsive and long enough for a
/// slow link to complete the handshake.
pub const QUIC_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// How long the client skips the QUIC probe after a failed attempt.
///
/// Without this, every reconnect in a UDP-blocked network would pay
/// the handshake timeout again.
pub const QUIC_PROBE_SKIP_SECS: i64 = 600;

/// How long the client waits for the gateway's answer to its `AUTH`
/// line.
///
/// A gateway that accepts the QUIC connection but never answers would
/// otherwise hang the client's session forever.
const AUTH_REPLY_TIMEOUT_SECS: u64 = 10;

/// The outcome of one connect-and-serve cycle.
///
/// The transport is part of the outcome because a session that
/// silently fell back must be distinguishable from a QUIC session.
#[non_exhaustive]
#[derive(Debug)]
pub enum SessionOutcome {
    /// The session was established and ended cleanly.
    Ended {
        /// The transport the session actually used.
        transport: crate::tunnel::TransportKind,
    },
    /// The session was established and ended with an error.
    Errored {
        /// The transport the session actually used.
        transport: crate::tunnel::TransportKind,
        /// What ended the session.
        error: TunnelError,
    },
    /// The session could not be established at all.
    NotConnected {
        /// The transport that was attempted, if one was.
        transport: Option<crate::tunnel::TransportKind>,
        /// Why the session could not be established.
        error: TunnelError,
    },
}

/// The tunnel client: it dials the gateway, serves the streams the
/// gateway opens and relays them to their targets.
pub struct TunnelClient {
    settings: TunSettings,
}

impl TunnelClient {
    /// Build the client from the settings the caller supplies.
    pub fn new(settings: TunSettings) -> Self {
        Self { settings }
    }

    /// The settings the client runs with.
    pub fn settings(&self) -> &TunSettings {
        &self.settings
    }

    /// Run the client: connect, serve, reconnect with a backoff,
    /// forever.
    ///
    /// The call never returns. A caller that needs to stop the client
    /// cancels the future it awaits, e.g. by selecting it against a
    /// signal:
    ///
    /// ```no_run
    /// # use pangolin_tun::TunnelClient;
    /// # async fn run(client: TunnelClient) {
    /// let (_shutdown, mut stopped) = tokio::sync::watch::channel(false);
    /// tokio::select! {
    ///     _ = client.run() => {}
    ///     _ = stopped.changed() => {}
    /// }
    /// # }
    /// ```
    ///
    /// The backoff runs from one second to thirty seconds, doubling,
    /// with at most 500 ms of jitter, and is reset to one second after
    /// a session that ended.
    pub async fn run(&self) {
        info!(
            "tun {} starting, target {} (transport: {})",
            self.settings.name, self.settings.server, self.settings.transport
        );

        const INITIAL_BACKOFF_SECS: u64 = 1;
        const MAX_BACKOFF_SECS: u64 = 30;
        const MAX_JITTER_MS: u64 = 500;

        let mut backoff_secs: u64 = INITIAL_BACKOFF_SECS;

        loop {
            match self.connect_once().await {
                SessionOutcome::Ended { transport } => {
                    info!(
                        "tun {} disconnected ({transport}), will reconnect",
                        self.settings.name
                    );
                    backoff_secs = INITIAL_BACKOFF_SECS;
                }
                SessionOutcome::Errored { transport, error } => {
                    warn!(
                        "tun {} session errored ({transport}): {error}, will reconnect",
                        self.settings.name
                    );
                    backoff_secs = INITIAL_BACKOFF_SECS;
                }
                SessionOutcome::NotConnected { transport, error } => {
                    error!(
                        "tun {} connect error ({transport:?}): {error}, reconnecting in {}s",
                        self.settings.name, backoff_secs,
                    );
                }
            }

            let jitter_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_millis() as u64)
                .unwrap_or(0)
                % (MAX_JITTER_MS + 1);
            sleep(Duration::from_millis(backoff_secs * 1000 + jitter_ms)).await;
            backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
        }
    }

    /// Run one connect-and-serve cycle and report its outcome.
    ///
    /// The cycle ends when the gateway closes the session, when the
    /// session fails, or when the client could not connect at all. The
    /// outcome names the transport that was actually used, so a caller
    /// can tell a QUIC session from a fallback session.
    pub async fn connect_once(&self) -> SessionOutcome {
        let (host, port) = match parse_server(&self.settings.server) {
            Ok(server) => server,
            Err(error) => {
                return SessionOutcome::NotConnected {
                    transport: None,
                    error,
                };
            }
        };

        let transport = match self.settings.transport {
            TransportSelector::Tcp => match self.connect_tcp(&host, port).await {
                Ok(transport) => transport,
                Err(error) => {
                    return SessionOutcome::NotConnected {
                        transport: Some(TransportKind::Tcp),
                        error,
                    };
                }
            },
            TransportSelector::Quic => match self.connect_quic(&host, port).await {
                Ok(transport) => transport,
                Err(error) => {
                    return SessionOutcome::NotConnected {
                        transport: Some(TransportKind::Quic),
                        error: error.into(),
                    };
                }
            },
            TransportSelector::Auto => {
                if self.quic_recently_failed() {
                    info!(
                        "tun {}: skipping the QUIC probe (the last attempt failed less than {}s ago)",
                        self.settings.name, QUIC_PROBE_SKIP_SECS
                    );
                    match self.connect_tcp(&host, port).await {
                        Ok(transport) => transport,
                        Err(error) => {
                            return SessionOutcome::NotConnected {
                                transport: Some(TransportKind::Tcp),
                                error,
                            };
                        }
                    }
                } else {
                    match self.connect_quic(&host, port).await {
                        Ok(transport) => transport,
                        Err(e) if quic_failure_falls_back(&e) => {
                            // The gateway could not be reached — the
                            // network most likely blocks UDP. The
                            // fallback is the right answer here.
                            warn!(
                                "tun {}: the QUIC attempt failed ({e}); falling back to the \
                                 WebSocket/TCP transport",
                                self.settings.name
                            );
                            self.record_quic_failure();
                            match self.connect_tcp(&host, port).await {
                                Ok(transport) => transport,
                                Err(error) => {
                                    return SessionOutcome::NotConnected {
                                        transport: Some(TransportKind::Tcp),
                                        error,
                                    };
                                }
                            }
                        }
                        Err(e) => {
                            // The gateway could not be **trusted**,
                            // or it refused the session. Falling
                            // back here would send the bearer token
                            // over the unencrypted WebSocket/TCP
                            // transport — to whoever is presenting
                            // the wrong certificate, or with no gain
                            // at all. That is the exact downgrade the
                            // QUIC transport exists to prevent, so
                            // refuse and let the operator fix it (or
                            // choose the fallback transport
                            // deliberately).
                            let reason = match &e {
                                QuicConnectError::Untrusted(_) => format!(
                                    "the gateway's QUIC certificate is not trusted ({e}); refusing \
                                     to fall back to the unencrypted WebSocket/TCP transport — \
                                     falling back would send the bearer token in cleartext"
                                ),
                                _ => format!(
                                    "the QUIC session was refused ({e}); not falling back to the \
                                     unencrypted WebSocket/TCP transport — it would carry the \
                                     bearer token in cleartext for no gain"
                                ),
                            };
                            error!(
                                "tun {}: {reason}. Fix the problem, or select the fallback \
                                 transport deliberately",
                                self.settings.name
                            );
                            return SessionOutcome::NotConnected {
                                transport: Some(TransportKind::Quic),
                                error: e.into(),
                            };
                        }
                    }
                }
            }
        };

        let kind = transport.kind();
        match serve_tun_session(&self.settings, transport).await {
            Ok(()) => SessionOutcome::Ended { transport: kind },
            Err(error) => SessionOutcome::Errored {
                transport: kind,
                error,
            },
        }
    }

    /// Connect over QUIC and authenticate on a control stream.
    ///
    /// The error says **whether** the gateway was unreachable or
    /// untrusted — the caller must not fall back to the unencrypted
    /// transport after a trust failure.
    async fn connect_quic(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<Arc<dyn TunnelTransport>, QuicConnectError> {
        let addrs = resolve_server(host, port)
            .await
            .map_err(|e| QuicConnectError::Unreachable(e.to_string()))?;
        let server_name = host.to_string();
        let pins = PinStore::open(&self.settings.pin_path).map_err(|e| {
            QuicConnectError::PinStore(format!(
                "the pin file {} could not be read: {e}",
                self.settings.pin_path.display()
            ))
        })?;

        let (transport, handshake) = self.connect_quic_over(&addrs, &server_name, &pins).await?;

        // The first contact is the weak spot of any trust-on-first-use
        // scheme: the operator compares this fingerprint against the
        // gateway's own log.
        info!(
            "tun {}: the gateway presented the QUIC certificate {} ({})",
            self.settings.name,
            handshake.fingerprint,
            if handshake.newly_pinned {
                "pinned"
            } else {
                "already pinned"
            }
        );

        // QUIC has no upgrade request to carry the token in, so the
        // client opens a control stream and authenticates there.
        //
        // A failure here is **not** "the gateway is unreachable": the
        // handshake completed, so the gateway was reached. Calling it
        // unreachable would let the client fall back to the
        // unencrypted transport and hand the bearer token to the very
        // gateway that just failed the exchange.
        let mut control = transport
            .open_stream()
            .await
            .map_err(|e| QuicConnectError::Refused(format!("open the QUIC control stream: {e}")))?;
        control
            .write_all(&encode_auth(
                &self.settings.token,
                &self.settings.name,
                TUNNEL_PROTOCOL_VERSION,
            ))
            .await
            .map_err(|e| QuicConnectError::Refused(format!("write the AUTH line: {e}")))?;
        control
            .flush()
            .await
            .map_err(|e| QuicConnectError::Refused(format!("flush the AUTH line: {e}")))?;
        let reply = tokio::time::timeout(
            Duration::from_secs(AUTH_REPLY_TIMEOUT_SECS),
            read_crlf_line(&mut control, MAX_INSTRUCTION_LEN),
        )
        .await
        .map_err(|_| {
            QuicConnectError::Refused(format!(
                "the gateway did not answer the AUTH line within {AUTH_REPLY_TIMEOUT_SECS}s"
            ))
        })?
        .map_err(|e| QuicConnectError::Refused(format!("read the AUTH reply: {e}")))?;
        match decode_auth_reply(reply.as_bytes())
            .map_err(|e| QuicConnectError::Refused(e.to_string()))?
        {
            Ok(version) => {
                if version != TUNNEL_PROTOCOL_VERSION {
                    return Err(QuicConnectError::Untrusted(protocol_version_mismatch(
                        TUNNEL_PROTOCOL_VERSION,
                        version,
                    )));
                }
            }
            Err(reason) => {
                return Err(QuicConnectError::Refused(format!(
                    "the gateway refused the tun: {reason}"
                )));
            }
        }

        info!(
            "tun {} connected to ngx {} over quic",
            self.settings.name, self.settings.server
        );
        Ok(Arc::new(transport))
    }

    /// Establish the QUIC connection, trying every address the
    /// gateway's name resolves to.
    ///
    /// The resolver's order is OS-dependent, and a gateway whose
    /// first address does not answer must not cost a fallback to the
    /// unencrypted transport — the next address is tried instead. A
    /// trust failure or a refusal is the same for every address, so
    /// it ends the attempt right away.
    async fn connect_quic_over(
        &self,
        addrs: &[SocketAddr],
        server_name: &str,
        pins: &PinStore,
    ) -> std::result::Result<(QuicClientTransport, QuicHandshake), QuicConnectError> {
        let mut last: Option<QuicConnectError> = None;
        for addr in addrs {
            match tokio::time::timeout(
                Duration::from_secs(QUIC_HANDSHAKE_TIMEOUT_SECS),
                QuicClientTransport::connect(*addr, server_name, pins),
            )
            .await
            {
                Ok(Ok(connected)) => return Ok(connected),
                Ok(Err(e)) if !matches!(e, QuicConnectError::Unreachable(_)) => return Err(e),
                Ok(Err(e)) => last = Some(e),
                Err(_) => {
                    last = Some(QuicConnectError::Unreachable(format!(
                        "the QUIC handshake to {addr} timed out after {QUIC_HANDSHAKE_TIMEOUT_SECS}s"
                    )))
                }
            }
        }
        Err(last.unwrap_or_else(|| {
            QuicConnectError::Unreachable(format!(
                "the server address {server_name} did not resolve to any address"
            ))
        }))
    }

    /// Connect over the WebSocket/TCP fallback transport.
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<Arc<dyn TunnelTransport>> {
        let tcp = TcpStream::connect((host, port)).await.map_err(|e| {
            TunnelError::Unreachable(format!("tcp connect to {}: {e}", self.settings.server))
        })?;
        let (mut tcp_read, mut tcp_write) = tcp.into_split();
        let path = format!("/tunnel?name={}", self.settings.name);
        let host_header = &self.settings.server;
        // The protocol version rides in the upgrade request — it is
        // the only handshake the TCP fallback has.
        let extra_headers = vec![(
            TUNNEL_VERSION_HEADER.to_string(),
            TUNNEL_PROTOCOL_VERSION.to_string(),
        )];
        let (req_bytes, key) =
            build_ws_upgrade_request(&path, host_header, &self.settings.token, &extra_headers);
        tcp_write
            .write_all(&req_bytes)
            .await
            .map_err(TunnelError::Io)?;
        tcp_write.flush().await.map_err(TunnelError::Io)?;
        read_ws_accept_response(&mut tcp_read, &key)
            .await
            .map_err(|e| TunnelError::Refused(format!("the gateway refused the upgrade: {e}")))?;
        let ws = fastwebsockets::WebSocket::after_handshake(
            OwnedTcpHalf {
                reader: tcp_read,
                writer: tcp_write,
            },
            WsRole::Client,
        );
        let tunnel = tunnel_over_websocket(ws, TunnelRole::Client);
        info!(
            "tun {} connected to ngx {} over the WebSocket/TCP transport",
            self.settings.name, self.settings.server
        );
        Ok(Arc::new(tunnel))
    }

    /// Whether the last QUIC attempt failed recently enough that the
    /// probe should be skipped.
    fn quic_recently_failed(&self) -> bool {
        let Ok(text) = std::fs::read_to_string(&self.settings.quic_failure_path) else {
            return false;
        };
        let Ok(failed_at) = text.trim().parse::<i64>() else {
            return false;
        };
        unix_now() - failed_at < QUIC_PROBE_SKIP_SECS
    }

    /// Record the time of the failed QUIC attempt so the next session
    /// goes straight to the fallback.
    fn record_quic_failure(&self) {
        // The record has to land in a directory that exists: without
        // it the write fails, the probe is not skipped and every
        // reconnect pays the handshake timeout again.
        if let Some(parent) = self.settings.quic_failure_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!(
                "tun {}: could not create {}: {e}",
                self.settings.name,
                parent.display()
            );
        }
        if let Err(e) = std::fs::write(&self.settings.quic_failure_path, unix_now().to_string()) {
            warn!(
                "tun {}: could not record the QUIC failure in {}: {}",
                self.settings.name,
                self.settings.quic_failure_path.display(),
                e
            );
        }
    }
}

/// The current time as a Unix timestamp in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Split `host:port` into the host and the port.
///
/// The host may be a name or an IP literal. Either way it is the
/// operator's gateway address, and the certificate is pinned by
/// fingerprint — so the name is only used for the TLS handshake
/// itself, never for verification.
fn parse_server(server: &str) -> Result<(String, u16)> {
    let (host, port) = server.rsplit_once(':').ok_or_else(|| {
        TunnelError::Invalid(format!("the server address {server:?} has no port"))
    })?;
    let port: u16 = port.parse().map_err(|_| {
        TunnelError::Invalid(format!("the server address {server:?} has a bad port"))
    })?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((host.to_string(), port))
}

/// Resolve `host` into the socket addresses it answers on.
///
/// Every address is returned: the resolver's order is OS-dependent,
/// and the client tries them in turn. The host name itself is what
/// the TLS handshake presents.
async fn resolve_server(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host((host, port)).await.map_err(|e| {
        TunnelError::Unreachable(format!("resolve the server address {host}:{port}: {e}"))
    })?;
    let addrs: Vec<SocketAddr> = addrs.collect();
    if addrs.is_empty() {
        return Err(TunnelError::Unreachable(format!(
            "the server address {host}:{port} did not resolve"
        )));
    }
    Ok(addrs)
}

struct OwnedTcpHalf {
    reader: tokio::net::tcp::OwnedReadHalf,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl AsyncRead for OwnedTcpHalf {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for OwnedTcpHalf {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// Run the tun-side accept loop: every stream the gateway opens is a
/// request the client has to relay to a backend.
async fn serve_tun_session(
    settings: &TunSettings,
    transport: Arc<dyn TunnelTransport>,
) -> Result<()> {
    let name = settings.name.clone();
    loop {
        let stream = match transport.accept_stream().await {
            Some(Ok(s)) => s,
            Some(Err(e)) => {
                warn!("tun {} accept error: {}", name, e);
                return Err(e);
            }
            None => {
                info!("tun {} session ended", name);
                return Ok(());
            }
        };

        let name_for_log = name.clone();
        tokio::spawn(async move {
            let dial = |host: &str, port: u16| {
                let host = host.to_owned();
                async move { dial_target(host, port).await }
            };
            if let Err(e) = serve_tunnel_stream(stream, dial).await {
                warn!("tun {} relay error: {}", name_for_log, e);
            }
        });
    }
}

/// Resolve the target and dial it.
///
/// The host is resolved **here**, in the operator's own network — a
/// backend that is only reachable from the tun's side is reachable
/// through the tunnel.
///
/// Every address the resolver returns is tried, not just the first:
/// `lookup_host` ordering is OS-dependent (Linux lists `::1` before
/// `127.0.0.1` for `localhost`), and the back-half of the connection
/// failures are "wrong address family" — the backend only listens on
/// v4 but the resolver hands us v6 first.
async fn dial_target(host: String, port: u16) -> Result<TcpStream> {
    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| {
            TunnelError::Io(std::io::Error::other(format!(
                "DNS lookup failed for {host}: {e}"
            )))
        })?;
    let mut last_err: Option<std::io::Error> = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                debug!(
                    "tun: connect to {} failed: {} — trying the next address",
                    addr, e
                );
                last_err = Some(e);
            }
        }
    }
    Err(TunnelError::Io(std::io::Error::other(format!(
        "no reachable address for {host}:{port}: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no addresses".into())
    ))))
}

/// Whether a failed QUIC attempt may fall back to the WebSocket/TCP
/// transport.
///
/// A gateway that cannot be **reached** may: the network most likely
/// blocks UDP, and the fallback is the only way through. A gateway
/// that cannot be **trusted** may not — the fallback is unencrypted,
/// so falling back would hand the bearer token to whoever is
/// presenting the wrong certificate. That is the exact downgrade the
/// QUIC transport exists to prevent, so the client refuses and the
/// operator has to fix the pin (or choose the fallback transport
/// deliberately).
fn quic_failure_falls_back(error: &QuicConnectError) -> bool {
    matches!(error, QuicConnectError::Unreachable(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A gateway that cannot be **reached** may fall back to the
    /// unencrypted transport — that is the "the network blocks UDP"
    /// case.
    #[test]
    fn an_unreachable_gateway_may_fall_back() {
        assert!(quic_failure_falls_back(&QuicConnectError::Unreachable(
            "connection refused".into()
        )));
    }

    /// A gateway that cannot be **trusted** may not: falling back
    /// would send the bearer token in cleartext to whoever is
    /// presenting the wrong certificate. Neither may a refused
    /// session or a pin store that cannot be written.
    #[test]
    fn an_untrusted_gateway_may_not_fall_back() {
        assert!(!quic_failure_falls_back(&QuicConnectError::Untrusted(
            "the certificate is not pinned".into()
        )));
        assert!(!quic_failure_falls_back(&QuicConnectError::Refused(
            "the gateway refused the tun".into()
        )));
        assert!(!quic_failure_falls_back(&QuicConnectError::PinStore(
            "the pin file is not writable".into()
        )));
    }

    /// The server address is split into the host and the port.
    #[test]
    fn the_server_address_is_split() {
        let (host, port) = parse_server("127.0.0.1:9001").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9001);
    }

    /// An IPv6 literal arrives bracketed; the brackets are stripped.
    #[test]
    fn the_server_address_strips_the_brackets_of_an_ipv6_literal() {
        let (host, port) = parse_server("[::1]:9001").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 9001);
    }

    /// The resolver's answers are all returned: the client tries them
    /// in turn, because the order is OS-dependent and a gateway whose
    /// first address does not answer must not cost a fallback to the
    /// unencrypted transport.
    #[tokio::test]
    async fn every_resolved_address_is_returned() {
        let addrs = resolve_server("localhost", 9001).await.unwrap();
        assert!(!addrs.is_empty(), "localhost must resolve to an address");
    }

    /// An address without a port is refused up front rather than at
    /// the first connect.
    #[test]
    fn the_server_address_without_port_is_refused() {
        assert!(parse_server("gateway.example.com").is_err());
        assert!(parse_server("gateway.example.com:not-a-port").is_err());
    }

    fn client_for(dir: &std::path::Path) -> TunnelClient {
        let settings = TunSettings {
            server: "127.0.0.1:9001".into(),
            token: "t".into(),
            name: "office".into(),
            transport: TransportSelector::Auto,
            pin_path: dir.join("tun.pins"),
            quic_failure_path: dir.join("tun.quic-fail"),
        };
        TunnelClient::new(settings)
    }

    /// A client that has never tried QUIC probes it on the next
    /// session.
    #[test]
    fn a_fresh_client_probes_quic() {
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(dir.path());
        assert!(
            !client.quic_recently_failed(),
            "a client that never tried QUIC must probe it"
        );
    }

    /// After a failed QUIC attempt the client skips the probe — and the
    /// record survives a restart, so a client that is restarted every
    /// few minutes does not pay the handshake timeout every time.
    #[test]
    fn a_failed_quic_attempt_skips_the_probe_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(dir.path());
        client.record_quic_failure();
        assert!(client.quic_recently_failed());

        // A "restart" — a new client reading the same directory.
        let restarted = client_for(dir.path());
        assert!(
            restarted.quic_recently_failed(),
            "the QUIC failure record must survive a restart"
        );
    }

    /// The client's relay keeps the **response** direction open after
    /// the gateway's direction ended.
    ///
    /// A backend that answers only after the request is complete has
    /// to reach the gateway — that is what the relay's half-close
    /// handling is for.
    #[tokio::test]
    async fn the_relay_keeps_the_response_direction_open_after_the_request_ended() {
        // A backend that answers only once it saw the end of the
        // request.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let backend_task = tokio::spawn(async move {
            let (mut backend, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = backend.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            // Wait for the half-close: the client shuts the backend's
            // write side down when the gateway's direction ended.
            let mut rest = Vec::new();
            backend.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            backend.write_all(b"pong").await.unwrap();
            backend.shutdown().await.unwrap();
        });

        let (mut gateway, tunnel) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            let dial = |host: &str, port: u16| {
                let host = host.to_owned();
                async move { dial_target(host, port).await }
            };
            serve_tunnel_stream(tunnel, dial).await
        });

        gateway
            .write_all(format!("CONNECT 127.0.0.1:{port}\r\n").as_bytes())
            .await
            .unwrap();
        gateway.flush().await.unwrap();
        assert_eq!(read_crlf_line(&mut gateway, 4096).await.unwrap(), "OK");

        // The gateway writes the request and ends its direction.
        gateway.write_all(b"ping").await.unwrap();
        gateway.flush().await.unwrap();
        gateway.shutdown().await.unwrap();

        // The response still arrives.
        let mut seen = Vec::new();
        gateway.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"pong");

        relay.await.unwrap().unwrap();
        backend_task.await.unwrap();
    }

    /// The client's relay keeps the **request** direction open after
    /// the backend's direction ended.
    ///
    /// A backend that answers and then hangs up must not cost the
    /// gateway the bytes it still had to send.
    #[tokio::test]
    async fn the_relay_keeps_the_request_direction_open_after_the_response_ended() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let backend_task = tokio::spawn(async move {
            let (mut backend, _) = listener.accept().await.unwrap();
            // Answer, then end the response direction.
            backend.write_all(b"pong").await.unwrap();
            backend.shutdown().await.unwrap();
            // The request direction is still open.
            let mut rest = Vec::new();
            backend.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, b"more");
        });

        let (mut gateway, tunnel) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            let dial = |host: &str, port: u16| {
                let host = host.to_owned();
                async move { dial_target(host, port).await }
            };
            serve_tunnel_stream(tunnel, dial).await
        });

        gateway
            .write_all(format!("CONNECT 127.0.0.1:{port}\r\n").as_bytes())
            .await
            .unwrap();
        gateway.flush().await.unwrap();
        assert_eq!(read_crlf_line(&mut gateway, 4096).await.unwrap(), "OK");

        // The gateway reads the answer, then sends what it still had
        // to say.
        let mut answered = Vec::new();
        gateway.read_to_end(&mut answered).await.unwrap();
        assert_eq!(answered, b"pong");
        gateway.write_all(b"more").await.unwrap();
        gateway.flush().await.unwrap();
        gateway.shutdown().await.unwrap();

        relay.await.unwrap().unwrap();
        backend_task.await.unwrap();
    }

    /// The skip expires: after the ten-minute window the client probes
    /// QUIC again, so a network that unblocks UDP is picked up
    /// without operator action.
    #[test]
    fn the_quic_probe_skip_expires() {
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(dir.path());
        client.record_quic_failure();
        // Backdate the record past the skip window.
        let old = unix_now() - QUIC_PROBE_SKIP_SECS - 60;
        std::fs::write(&client.settings.quic_failure_path, old.to_string()).unwrap();
        assert!(
            !client.quic_recently_failed(),
            "the client must probe QUIC again after the skip window"
        );
    }
}
