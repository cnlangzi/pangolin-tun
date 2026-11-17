//! The harness every integration test shares.
//!
//! Everything here is built from the crate's **public** API, so the
//! suite exercises the crate the way a consumer of the published crate
//! does: a gateway that speaks both transports, on one port number.
//!
//! The gateway counts what it saw — the QUIC connections, the TCP
//! connections and the UDP datagrams — so that "the tun did not fall
//! back" is an assertion and not an inference.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pangolin_tun::{
    QuicCert, QuicServerTransport, Result, SessionOutcome, TUNNEL_PROTOCOL_VERSION, TransportKind,
    TransportSelector, TunSettings, TunnelClient, TunnelRole, TunnelStream, TunnelTransport,
    WsRole, WsUpgradeRequest, YamuxTunnel, bind_endpoint, decode_auth, encode_auth_reply,
    encode_connect, read_crlf_line, read_ws_upgrade_request, tunnel_over_websocket, wrap_websocket,
    write_http_error, write_ws_accept_response,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// The longest a test waits for something that should happen at once.
pub const DEADLINE: Duration = Duration::from_secs(15);

/// The longest a test waits for something that waits out a timeout the
/// crate defines — the AUTH reply timeout is 10 seconds.
pub const LONG_DEADLINE: Duration = Duration::from_secs(30);

/// The bearer token the tun sends.
pub const TOKEN: &str = "secret-token";

/// The name the tun registers under.
pub const NAME: &str = "office";

/// How the QUIC half of the gateway behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicMode {
    /// A real QUIC endpoint with a self-signed certificate.
    Serve,
    /// A UDP socket that swallows every datagram: a network that
    /// blocks UDP.
    Blackhole,
}

/// How the gateway answers the tun's AUTH line.
#[derive(Debug, Clone)]
pub enum AuthReply {
    /// `OK <TUNNEL_PROTOCOL_VERSION>`.
    Accept,
    /// `OK <version>` with a different protocol version.
    Version(u32),
    /// `ERR <reason>`.
    Refuse(String),
    /// Nothing at all: the gateway accepts the connection and stays
    /// silent.
    Silent,
}

/// How the gateway answers the WebSocket upgrade request.
#[derive(Debug, Clone)]
pub enum UpgradeReply {
    /// `101 Switching Protocols`, then the yamux tunnel.
    Accept,
    /// An HTTP error, e.g. `401 Unauthorized`.
    Refuse { status: u16, reason: String },
}

/// A QUIC session the gateway accepted.
pub struct QuicSession {
    /// The tun's AUTH line: token, name and protocol version.
    pub auth: (String, String, u32),
    /// The transport the session runs on.
    pub transport: Arc<dyn TunnelTransport>,
    /// The QUIC connection, so a test can close the session the way a
    /// gateway that goes away does.
    pub connection: quinn::Connection,
    /// The control stream the tun authenticated on. It stays open for
    /// the whole session: a gateway that dropped it would end the
    /// tun's control stream before the AUTH line was answered.
    pub control: TunnelStream,
}

/// A WebSocket/TCP session the gateway accepted.
pub struct TcpSession {
    /// The tun's upgrade request.
    pub upgrade: WsUpgradeRequest,
    /// The yamux tunnel the session runs on. A refused upgrade has no
    /// tunnel.
    pub tunnel: Option<YamuxTunnel>,
}

/// A gateway session, on either transport.
pub enum Session {
    /// A session over QUIC.
    Quic(QuicSession),
    /// A session over the WebSocket/TCP transport.
    Tcp(TcpSession),
}

impl QuicSession {
    /// The session as a transport-agnostic session.
    pub fn into_session(self) -> Session {
        Session::Quic(self)
    }

    /// End the session, the way a gateway that goes away does.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"done");
    }
}

impl TcpSession {
    /// The session as a transport-agnostic session.
    pub fn into_session(self) -> Session {
        Session::Tcp(self)
    }

    /// End the session, the way a gateway that goes away does.
    pub fn close(&self) {
        if let Some(tunnel) = &self.tunnel {
            tunnel.bridge_abort.abort();
        }
    }
}

/// The transport a session outcome names, if it names one.
pub fn outcome_transport(outcome: &SessionOutcome) -> Option<TransportKind> {
    match outcome {
        SessionOutcome::Ended { transport } => Some(*transport),
        SessionOutcome::Errored { transport, .. } => Some(*transport),
        SessionOutcome::NotConnected { transport, .. } => *transport,
        _ => None,
    }
}

/// The current time as a Unix timestamp in seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Session {
    /// Open a new stream towards the tun.
    pub async fn open_stream(&self) -> Result<TunnelStream> {
        match self {
            Session::Quic(session) => session.transport.open_stream().await,
            Session::Tcp(session) => {
                let tunnel = session
                    .tunnel
                    .as_ref()
                    .expect("a refused upgrade has no tunnel");
                // The inherent method hands out a yamux stream; the
                // trait method hands out the boxed byte stream the
                // tunnel speaks in.
                TunnelTransport::open_stream(tunnel).await
            }
        }
    }

    /// End the session, the way a gateway that goes away does.
    pub fn close(&self) {
        match self {
            Session::Quic(session) => session.close(),
            Session::Tcp(session) => session.close(),
        }
    }
}

/// A client that has connected to a gateway, and the session the
/// gateway accepted.
pub struct Wired {
    /// The transport the session runs on.
    pub kind: TransportKind,
    /// The gateway the client dialed.
    pub gateway: Gateway,
    /// The session the gateway accepted.
    pub session: Session,
    /// The client's connect-and-serve cycle.
    pub client: tokio::task::JoinHandle<SessionOutcome>,
}

impl Wired {
    /// End the session and wait for the client's outcome.
    ///
    /// The session's receipt comes with it: the gateway's counters say
    /// which transport the session ran on, so a session that quietly
    /// fell back cannot pass.
    pub async fn outcome(self) -> SessionOutcome {
        self.session.close();
        let Self {
            kind,
            gateway,
            client,
            ..
        } = self;
        let outcome = tokio::time::timeout(DEADLINE, client)
            .await
            .expect("the session must not hang")
            .expect("the client must not panic");
        match kind {
            TransportKind::Quic => {
                assert_eq!(
                    gateway.quic_connections(),
                    1,
                    "the tun must have opened exactly one QUIC connection"
                );
                assert_eq!(
                    gateway.tcp_connections(),
                    0,
                    "the tun must not have opened a TCP connection"
                );
            }
            TransportKind::Tcp => {
                assert_eq!(
                    gateway.tcp_connections(),
                    1,
                    "the tun must have opened exactly one TCP connection"
                );
                assert_eq!(
                    gateway.quic_connections(),
                    0,
                    "the tun must not have contacted the QUIC endpoint"
                );
            }
        }
        outcome
    }
}

/// The gateway's shared state.
struct Inner {
    quic_connections: AtomicUsize,
    tcp_connections: AtomicUsize,
    udp_datagrams: Arc<AtomicUsize>,
    quic_sessions: tokio::sync::Mutex<mpsc::UnboundedReceiver<QuicSession>>,
    tcp_sessions: tokio::sync::Mutex<mpsc::UnboundedReceiver<TcpSession>>,
    /// The QUIC endpoint has to outlive the connections it carries:
    /// dropping it tears them down.
    endpoint: Option<quinn::Endpoint>,
}

/// A test gateway: one address serving both transports.
///
/// The QUIC endpoint and the TCP listener share one port number, the
/// way the production gateway does — so a client that falls back
/// opens a TCP connection to the very address its QUIC attempt went
/// to, and the counters see it.
pub struct Gateway {
    /// The address the tun dials.
    pub addr: String,
    /// The fingerprint of the QUIC certificate; empty when the UDP
    /// port is blackholed.
    pub fingerprint: String,
    inner: Arc<Inner>,
}

impl Gateway {
    /// Bind a gateway that serves both transports on one port number.
    ///
    /// The TCP listener takes a port the kernel picks, and the UDP
    /// half is bound on the same number. The two live in separate port
    /// spaces, so the pair almost always fits; when it does not, the
    /// bind is retried with a fresh TCP port.
    pub async fn bind(quic: QuicMode, auth: AuthReply, upgrade: UpgradeReply) -> Gateway {
        let cert = QuicCert::generate().unwrap();
        let udp_datagrams = Arc::new(AtomicUsize::new(0));
        for _ in 0..16 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let addr = SocketAddr::from(([127, 0, 0, 1], port));

            let endpoint = match quic {
                QuicMode::Serve => match bind_endpoint(addr, &cert) {
                    Ok(endpoint) => Some(endpoint),
                    Err(_) => continue,
                },
                QuicMode::Blackhole => match UdpSocket::bind(addr).await {
                    Ok(socket) => {
                        let counted = udp_datagrams.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 2048];
                            loop {
                                if socket.recv_from(&mut buf).await.is_err() {
                                    break;
                                }
                                counted.fetch_add(1, Ordering::SeqCst);
                            }
                        });
                        None
                    }
                    Err(_) => continue,
                },
            };

            let (quic_tx, quic_rx) = mpsc::unbounded_channel();
            let (tcp_tx, tcp_rx) = mpsc::unbounded_channel();
            let inner = Arc::new(Inner {
                quic_connections: AtomicUsize::new(0),
                tcp_connections: AtomicUsize::new(0),
                udp_datagrams: udp_datagrams.clone(),
                quic_sessions: tokio::sync::Mutex::new(quic_rx),
                tcp_sessions: tokio::sync::Mutex::new(tcp_rx),
                endpoint: endpoint.clone(),
            });

            if let Some(endpoint) = endpoint {
                let counted = Arc::clone(&inner);
                tokio::spawn(async move {
                    loop {
                        let Some(incoming) = endpoint.accept().await else {
                            break;
                        };
                        // The attempt is counted before the handshake
                        // completes: a tun that reached the gateway and
                        // was refused on trust did open a QUIC
                        // connection.
                        counted.quic_connections.fetch_add(1, Ordering::SeqCst);
                        let Ok(connection) = incoming.await else {
                            continue;
                        };
                        let auth = auth.clone();
                        let tx = quic_tx.clone();
                        tokio::spawn(async move {
                            serve_quic(connection, auth, tx).await;
                        });
                    }
                });
            }

            let counted = Arc::clone(&inner);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    counted.tcp_connections.fetch_add(1, Ordering::SeqCst);
                    let upgrade = upgrade.clone();
                    let tx = tcp_tx.clone();
                    tokio::spawn(async move {
                        serve_tcp(stream, upgrade, tx).await;
                    });
                }
            });

            return Gateway {
                addr: addr.to_string(),
                fingerprint: match quic {
                    QuicMode::Serve => cert.fingerprint.clone(),
                    QuicMode::Blackhole => String::new(),
                },
                inner,
            };
        }
        panic!("no port number carried both transports");
    }

    /// The number of QUIC connections the gateway accepted.
    pub fn quic_connections(&self) -> usize {
        self.inner.quic_connections.load(Ordering::SeqCst)
    }

    /// The number of TCP connections the gateway accepted.
    pub fn tcp_connections(&self) -> usize {
        self.inner.tcp_connections.load(Ordering::SeqCst)
    }

    /// The number of UDP datagrams the blackhole received.
    pub fn udp_datagrams(&self) -> usize {
        self.inner.udp_datagrams.load(Ordering::SeqCst)
    }

    /// Accept the tun's QUIC connection, read the AUTH line on the
    /// control stream and answer it the way `auth` says.
    ///
    /// The parsed handshake comes back even when the gateway refuses,
    /// so a test can assert on what the tun sent.
    pub async fn accept_quic(&self) -> QuicSession {
        let mut rx = self.inner.quic_sessions.lock().await;
        rx.recv()
            .await
            .expect("the gateway accepted no QUIC session")
    }

    /// Accept the tun's WebSocket/TCP connection, read the upgrade
    /// request and answer it the way `upgrade` says.
    pub async fn accept_tcp(&self) -> TcpSession {
        let mut rx = self.inner.tcp_sessions.lock().await;
        rx.recv()
            .await
            .expect("the gateway accepted no WebSocket session")
    }

    /// Accept the tun's session on the given transport.
    pub async fn accept(&self, kind: TransportKind) -> Session {
        match kind {
            TransportKind::Quic => Session::Quic(self.accept_quic().await),
            TransportKind::Tcp => Session::Tcp(self.accept_tcp().await),
        }
    }
}

/// Serve one QUIC session: read the AUTH line on the control stream
/// and answer it.
async fn serve_quic(
    connection: quinn::Connection,
    auth: AuthReply,
    tx: mpsc::UnboundedSender<QuicSession>,
) {
    let transport = Arc::new(QuicServerTransport::new(connection.clone()));
    let Some(Ok(mut control)) = transport.accept_stream().await else {
        return;
    };
    let Ok(line) = read_crlf_line(&mut control).await else {
        return;
    };
    let parsed = decode_auth(line.as_bytes())
        .unwrap_or_else(|e| panic!("the tun's AUTH line must parse: {e}: {line:?}"));
    match auth {
        AuthReply::Accept => {
            let _ = control
                .write_all(&encode_auth_reply(Ok(TUNNEL_PROTOCOL_VERSION)))
                .await;
            let _ = control.flush().await;
        }
        AuthReply::Version(version) => {
            let _ = control.write_all(&encode_auth_reply(Ok(version))).await;
            let _ = control.flush().await;
        }
        AuthReply::Refuse(reason) => {
            let _ = control.write_all(&encode_auth_reply(Err(&reason))).await;
            let _ = control.flush().await;
            // The connection is left to the tun's teardown: closing it
            // here would drop the ERR line before the tun read it.
        }
        AuthReply::Silent => {}
    }
    let _ = tx.send(QuicSession {
        auth: parsed,
        transport,
        connection,
        control,
    });
}

/// Serve one WebSocket/TCP session: read the upgrade request and
/// answer it.
async fn serve_tcp(
    mut stream: TcpStream,
    upgrade: UpgradeReply,
    tx: mpsc::UnboundedSender<TcpSession>,
) {
    let Ok(request) = read_ws_upgrade_request(&mut stream).await else {
        return;
    };
    match upgrade {
        UpgradeReply::Accept => {
            let Some(key) = request.sec_websocket_key.clone() else {
                return;
            };
            if write_ws_accept_response(&mut stream, &key).await.is_err() {
                return;
            }
            let ws = wrap_websocket(stream, WsRole::Server);
            let tunnel = tunnel_over_websocket(ws, TunnelRole::Server);
            let _ = tx.send(TcpSession {
                upgrade: request,
                tunnel: Some(tunnel),
            });
        }
        UpgradeReply::Refuse { status, reason } => {
            let _ = write_http_error(&mut stream, status, &reason).await;
            let _ = stream.shutdown().await;
            let _ = tx.send(TcpSession {
                upgrade: request,
                tunnel: None,
            });
        }
    }
}

/// A backend that hands every accepted connection to `handle`.
///
/// The closure writes the scenario's behaviour: echo every byte,
/// answer only after the request side closed, emit an endless
/// response, answer with a fixed HTTP status.
///
/// The returned handle is the accept loop: it runs until the test's
/// runtime ends, so a test asserts on the bytes it received rather
/// than on the handle.
pub async fn backend<F, Fut>(handle: F) -> (u16, tokio::task::JoinHandle<()>)
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = Arc::new(handle);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let handle = Arc::clone(&handle);
            tokio::spawn(async move { handle(stream).await });
        }
    });
    (port, task)
}

/// A backend that echoes every byte it receives.
pub async fn echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    backend(|mut stream| async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
            stream.flush().await.unwrap();
        }
    })
    .await
}

/// A tun client for `address`, with its state files in `dir`.
pub fn client_at(dir: &Path, address: &str, transport: TransportSelector) -> TunnelClient {
    let settings = TunSettings {
        server: address.to_string(),
        token: TOKEN.to_string(),
        name: NAME.to_string(),
        transport,
        pin_path: dir.join("tun.pins"),
        quic_failure_path: dir.join("tun.quic-fail"),
    };
    TunnelClient::new(settings)
}

/// A tun client for `gateway`, with its state files in `dir`.
pub fn client(dir: &Path, gateway: &Gateway, transport: TransportSelector) -> TunnelClient {
    client_at(dir, &gateway.addr, transport)
}

/// The transport selector that pins a client to `kind`.
pub fn selector_for(kind: TransportKind) -> TransportSelector {
    match kind {
        TransportKind::Quic => TransportSelector::Quic,
        TransportKind::Tcp => TransportSelector::Tcp,
    }
}

/// Wait for the backend to report what it received, within the
/// deadline.
pub async fn received<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(DEADLINE, rx.recv())
        .await
        .expect("the backend must not hang")
        .expect("the backend reported nothing")
}

/// Write `bytes` into the tunnel and read the same number of bytes
/// back, within the deadline.
pub async fn round_trip(stream: &mut TunnelStream, bytes: &[u8]) -> Vec<u8> {
    tokio::time::timeout(DEADLINE, stream.write_all(bytes))
        .await
        .expect("the request must not hang")
        .expect("write the request");
    tokio::time::timeout(DEADLINE, stream.flush())
        .await
        .expect("the request must not hang")
        .expect("flush the request");
    let mut echoed = vec![0u8; bytes.len()];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut echoed))
        .await
        .expect("the answer must not hang")
        .expect("read the answer");
    echoed
}

/// Run a scenario once per transport.
///
/// The gateway serves the transport, the client dials it with the
/// transport pinned, and the body drives the session the gateway
/// accepted.
pub async fn each_transport<B, Fut>(body: B)
where
    B: Fn(Wired) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for kind in [TransportKind::Quic, TransportKind::Tcp] {
        let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
        let dir = tempfile::tempdir().unwrap();
        let client = client(dir.path(), &gateway, selector_for(kind));
        let task = tokio::spawn(async move { client.connect_once().await });
        let session = tokio::time::timeout(DEADLINE, gateway.accept(kind))
            .await
            .expect("the gateway must not hang");
        tokio::time::timeout(
            DEADLINE,
            body(Wired {
                kind,
                gateway,
                session,
                client: task,
            }),
        )
        .await
        .expect("the scenario must not hang");
    }
}

/// Open a stream to the tun and write the CONNECT instruction.
pub async fn open_stream(session: &Session, host: &str, port: u16) -> TunnelStream {
    let mut stream = tokio::time::timeout(DEADLINE, session.open_stream())
        .await
        .expect("the stream must not hang")
        .expect("open the stream");
    tokio::time::timeout(DEADLINE, stream.write_all(&encode_connect(host, port)))
        .await
        .expect("the CONNECT instruction must not hang")
        .expect("write the CONNECT instruction");
    tokio::time::timeout(DEADLINE, stream.flush())
        .await
        .expect("the CONNECT instruction must not hang")
        .expect("flush the CONNECT instruction");
    stream
}

/// Open a stream to the tun and check that it accepted the target.
pub async fn connect_to(session: &Session, host: &str, port: u16) -> TunnelStream {
    let mut stream = open_stream(session, host, port).await;
    let reply = tokio::time::timeout(DEADLINE, read_crlf_line(&mut stream))
        .await
        .expect("the CONNECT reply must not hang")
        .expect("read the CONNECT reply");
    assert_eq!(reply, "OK", "the tun must accept the target");
    stream
}
