//! The gateway's QUIC endpoint on a socket the caller owns.
//!
//! The crate binds the socket itself when it binds the endpoint, so a
//! caller cannot hand it a socket that already carries `SO_REUSEPORT`
//! — and a handover between two generations of the gateway needs
//! exactly that: the incoming generation binds the address the
//! outgoing generation still holds.
//!
//! These tests drive `bind_endpoint_with_socket` the way a gateway
//! would, through the crate's public API only.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::DEADLINE;
use pangolin_tun::{
    Error, PinStore, QuicBiStream, QuicCert, QuicClientTransport, TunnelTransport, bind_endpoint,
    bind_endpoint_with_socket,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The server name the tests dial the gateway under.
///
/// The tunnel's certificate is self-signed and the pin replaces
/// rustls' hostname check, so the name is the test's to choose.
const SERVER_NAME: &str = "pangolin-tunnel";

/// A generated certificate for the gateway's endpoint.
fn certificate() -> QuicCert {
    QuicCert::generate().unwrap()
}

/// The message of an [`Error::Invalid`].
fn invalid_message(err: Error) -> String {
    match err {
        Error::Invalid(message) => message,
        other => panic!("the socket must be refused with an invalid error: {other}"),
    }
}

/// Write `bytes` into the stream and read the same number of bytes
/// back, if the session is still alive.
///
/// A session that lost its packets to another socket of the group
/// goes quiet: the write or the read never completes. `within` bounds
/// the wait.
async fn round_trip<S>(within: Duration, stream: &mut S, bytes: &[u8]) -> Option<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(within, async {
        stream.write_all(bytes).await.ok()?;
        let mut echoed = vec![0u8; bytes.len()];
        stream.read_exact(&mut echoed).await.ok()?;
        Some(echoed)
    })
    .await
    .ok()
    .flatten()
}

/// The endpoint serves the tunnel's traffic: the client's handshake
/// completes, the fingerprint it reports is the certificate's, and a
/// stream carries bytes in both directions.
#[tokio::test]
async fn an_endpoint_on_a_caller_bound_socket_carries_a_stream() {
    let cert = certificate();
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    let endpoint = bind_endpoint_with_socket(addr, socket, &cert).unwrap();
    serve(endpoint, Arc::new(AtomicUsize::new(0)));

    let dir = tempfile::tempdir().unwrap();
    let pins = PinStore::open(dir.path().join("tun.pins")).unwrap();
    let (client, handshake) = QuicClientTransport::connect(addr, SERVER_NAME, &pins)
        .await
        .expect("the handshake must succeed");
    assert_eq!(
        handshake.fingerprint, cert.fingerprint,
        "the client must see the certificate the gateway was given"
    );
    assert!(handshake.newly_pinned, "the first contact pins the gateway");

    let mut stream = client.open_stream().await.expect("open the stream");
    let echoed = round_trip(DEADLINE, &mut stream, b"ping")
        .await
        .expect("the stream must carry the bytes");
    assert_eq!(echoed, b"ping");
}

/// The endpoint the crate binds itself keeps its error when there is
/// no runtime: an existing caller must not see a different failure
/// after the upgrade.
#[test]
fn binding_without_a_tokio_runtime_stays_an_io_error() {
    let cert = certificate();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let err = bind_endpoint(addr, &cert).expect_err("the bind must fail without a runtime");
    assert!(matches!(err, Error::Io(_)), "{err}");
}

/// A socket that was never bound is refused: the endpoint would be
/// alive but never receive a datagram.
#[tokio::test]
async fn an_unbound_socket_is_refused() {
    use socket2::{Domain, Protocol, Socket, Type};
    let cert = certificate();
    let socket: UdpSocket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .unwrap()
        .into();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let message = invalid_message(
        bind_endpoint_with_socket(addr, socket, &cert).expect_err("the socket must be refused"),
    );
    assert!(
        message.contains("not bound"),
        "the message must say the socket is not bound: {message}"
    );
}

/// A socket bound to another address is refused: the endpoint would
/// sit somewhere the caller does not expect.
#[tokio::test]
async fn a_socket_bound_to_another_address_is_refused() {
    let cert = certificate();
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let bound = socket.local_addr().unwrap();
    let claimed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), bound.port());
    let message = invalid_message(
        bind_endpoint_with_socket(claimed, socket, &cert).expect_err("the socket must be refused"),
    );
    assert!(
        message.contains(&bound.to_string()) && message.contains(&claimed.to_string()),
        "the message must name both addresses: {message}"
    );
}

/// The endpoint needs a tokio runtime — quinn registers the socket
/// with the runtime's reactor.
#[test]
fn a_call_outside_a_tokio_runtime_is_refused() {
    let cert = certificate();
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    let message = invalid_message(
        bind_endpoint_with_socket(addr, socket, &cert).expect_err("the socket must be refused"),
    );
    assert!(
        message.contains("tokio runtime"),
        "the message must say a tokio runtime is required: {message}"
    );
}

/// Accept connections on `endpoint` and echo every byte of every
/// stream, counting the connections that came up.
fn serve(endpoint: quinn::Endpoint, count: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let Ok(connection) = incoming.await else {
                continue;
            };
            tokio::spawn(async move {
                while let Ok((send, recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let mut stream = QuicBiStream::new(send, recv);
                        let mut buf = vec![0u8; 4096];
                        loop {
                            // The trait method, not quinn's inherent
                            // one: quinn's returns its own error type.
                            match AsyncReadExt::read(&mut stream, &mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// The reuseport group
// ---------------------------------------------------------------------------
//
// The `SO_REUSEPORT` group is Linux behaviour: the kernel picks the
// socket that receives a connection by the hash of the connection's
// 4-tuple, and other systems hand the traffic to the socket that was
// bound last.

/// A pin store that trusts `cert` already.
#[cfg(target_os = "linux")]
fn pins_for(cert: &QuicCert) -> (tempfile::TempDir, PinStore) {
    let dir = tempfile::tempdir().unwrap();
    let pins = PinStore::open(dir.path().join("tun.pins")).unwrap();
    pins.add(&cert.fingerprint).unwrap();
    (dir, pins)
}

/// Wait until `ready` holds, within `within`.
///
/// The endpoints count a connection when they accept it, and the
/// client's handshake can be over before the accept loop was polled —
/// so a test that counts has to wait for the count.
#[cfg(target_os = "linux")]
async fn wait_for(within: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if ready() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A QUIC client that dials the gateway from a chosen source port.
///
/// The kernel picks the socket that receives a connection out of a
/// reuseport group by the connection's 4-tuple hash, so a test that
/// wants both sockets of the group to serve a connection has to vary
/// the source port. The crate's own client picks its own.
#[cfg(target_os = "linux")]
fn client_endpoint(source: SocketAddr, pins: &PinStore) -> quinn::Endpoint {
    use pangolin_tun::{PinState, PinningVerifier, TUNNEL_ALPN, transport_config};

    pangolin_tun::install_crypto_provider();
    let state = Arc::new(PinState::default());
    let verifier = PinningVerifier::new(pins.pins(), state.clone(), pins.path().to_path_buf());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![TUNNEL_ALPN.to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(quic_config));
    config.transport_config(Arc::new(transport_config()));

    // The port is the test's to choose; the kernel takes over when
    // it is taken already.
    let socket = UdpSocket::bind(source)
        .or_else(|_| UdpSocket::bind(SocketAddr::new(source.ip(), 0)))
        .expect("bind the client's socket");
    let runtime = quinn::default_runtime().expect("a tokio runtime");
    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime).unwrap();
    endpoint.set_default_client_config(config);
    endpoint
}

/// Complete the handshake against the gateway.
#[cfg(target_os = "linux")]
async fn dial(endpoint: &quinn::Endpoint, addr: SocketAddr) -> quinn::Connection {
    let connecting = endpoint
        .connect(addr, SERVER_NAME)
        .expect("dial the gateway");
    tokio::time::timeout(DEADLINE, connecting)
        .await
        .expect("the handshake must not hang")
        .expect("the handshake must succeed")
}

/// The bytes a session carries, if it is still alive.
///
/// A session that lost its packets to another socket of the group
/// goes quiet: the write or the read never completes. A session that
/// was closed outright cannot open a stream at all.
#[cfg(target_os = "linux")]
async fn carried_bytes(connection: &quinn::Connection, within: Duration) -> Option<Vec<u8>> {
    let (send, recv) = connection.open_bi().await.ok()?;
    let mut stream = QuicBiStream::new(send, recv);
    round_trip(within, &mut stream, b"ping").await
}

/// A UDP socket with `SO_REUSEPORT` set, bound to `addr`.
///
/// The option has to be set before the bind — that is the whole point
/// of the caller's socket: the crate binds the socket internally, so
/// it cannot set the option itself.
#[cfg(target_os = "linux")]
fn reuse_port_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    let addr: socket2::SockAddr = addr.into();
    socket.bind(&addr)?;
    Ok(socket.into())
}

/// Two sockets with `SO_REUSEPORT` hold the same address: the
/// handover between two generations of the gateway.
///
/// The kernel picks the socket that receives a connection by the hash
/// of the connection's 4-tuple, so the two sockets share the
/// connections and neither starves.
///
/// A connection that was already up when the second socket joined is
/// **not** guaranteed to keep it: the group's socket array grew, and
/// the flow hash now picks between the two sockets — a flow whose hash
/// lands on the socket that joined is delivered to an endpoint that
/// knows nothing about it, and the session goes quiet. Measured on
/// Linux, about half of the sessions that were up lose their packets
/// that way. The test asserts what the group does guarantee: both
/// sockets serve connections, the sessions it served are alive, and
/// the tun is never locked out.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn two_sockets_with_reuse_port_share_the_address() {
    let cert = certificate();
    let (_dir, pins) = pins_for(&cert);

    // The outgoing generation binds the address with the option set.
    let socket = reuse_port_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    let first = bind_endpoint_with_socket(addr, socket, &cert).unwrap();

    // The address is held: the same bind without the option fails.
    let plain = UdpSocket::bind(addr);
    assert_eq!(
        plain.as_ref().unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse,
        "the port must stay with the socket that holds it"
    );

    let first_count = Arc::new(AtomicUsize::new(0));
    serve(first, first_count.clone());

    // A tun connects to the outgoing generation.
    let tun = client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20000),
        &pins,
    );
    let session = dial(&tun, addr).await;

    // The incoming generation takes the same address the same way.
    let socket = reuse_port_socket(addr).unwrap();
    let second = bind_endpoint_with_socket(addr, socket, &cert).unwrap();
    let second_count = Arc::new(AtomicUsize::new(0));
    serve(second, second_count.clone());

    // The session that was up before the join may have lost its
    // packets to the socket that joined. What it must never do is
    // answer with another session's bytes: a tunnel that carries
    // another tun's traffic is worse than one that goes quiet.
    if let Some(echoed) = carried_bytes(&session, Duration::from_secs(3)).await {
        assert_eq!(echoed, b"ping", "a live session must carry its own bytes");
    }

    // Both sockets of the group serve connections: the kernel spreads
    // them over the group, and which socket gets a given connection is
    // not fixed.
    let mut clients = Vec::new();
    for attempt in 1..64u16 {
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20000 + attempt);
        let endpoint = client_endpoint(source, &pins);
        let connection = dial(&endpoint, addr).await;
        clients.push((endpoint, connection));
        if wait_for(Duration::from_millis(200), || {
            first_count.load(Ordering::SeqCst) > 0 && second_count.load(Ordering::SeqCst) > 0
        })
        .await
        {
            break;
        }
    }
    assert!(
        first_count.load(Ordering::SeqCst) > 0,
        "the first socket of the group must serve a connection"
    );
    assert!(
        second_count.load(Ordering::SeqCst) > 0,
        "the second socket of the group must serve a connection"
    );

    // Every connection a client opened was accepted by one of the two
    // endpoints: the group hands every one of them to a socket.
    assert!(
        wait_for(DEADLINE, || {
            first_count.load(Ordering::SeqCst) + second_count.load(Ordering::SeqCst)
                == clients.len() + 1
        })
        .await,
        "every connection must be accepted by one of the two endpoints"
    );

    // And the sessions the group served are alive: they carry bytes.
    // Their flow was hashed after the group grew, so it does not move
    // again.
    for (_, connection) in &clients {
        let echoed = carried_bytes(connection, DEADLINE)
            .await
            .expect("a session the group served must carry the bytes");
        assert_eq!(echoed, b"ping");
    }

    // The tun is never locked out: the same client — the same source
    // port — comes back and is served again.
    let reconnect = dial(&tun, addr).await;
    let echoed = carried_bytes(&reconnect, DEADLINE)
        .await
        .expect("the tun must be served again");
    assert_eq!(echoed, b"ping");
}
