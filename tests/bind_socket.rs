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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pangolin_tun::{
    Error, PinStore, QuicCert, QuicClientTransport, TunnelTransport, bind_endpoint,
    bind_endpoint_with_socket,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The longest a test waits for something that should happen at once.
const DEADLINE: Duration = Duration::from_secs(15);

/// The server name the tests dial the gateway under.
///
/// The tunnel's certificate is self-signed and the pin replaces
/// rustls' hostname check, so the name is the test's to choose.
const SERVER_NAME: &str = "pangolin-tunnel";

/// A generated certificate for the gateway's endpoint.
fn certificate() -> QuicCert {
    QuicCert::generate().unwrap()
}

/// A pin store that trusts `cert` already.
#[cfg(unix)]
fn pins_for(cert: &QuicCert) -> (tempfile::TempDir, PinStore) {
    let dir = tempfile::tempdir().unwrap();
    let pins = PinStore::open(dir.path().join("tun.pins")).unwrap();
    pins.add(&cert.fingerprint).unwrap();
    (dir, pins)
}

/// The message of an [`Error::Invalid`].
fn invalid_message(err: Error) -> String {
    match err {
        Error::Invalid(message) => message,
        other => panic!("the socket must be refused with an invalid error: {other}"),
    }
}

/// Wait until `ready` holds, within `within`.
///
/// The endpoints count a connection when they accept it, and the
/// client's handshake can be over before the accept loop was polled —
/// so a test that counts has to wait for the count.
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

/// Write `bytes` into the connection and read the same number of bytes
/// back.
async fn round_trip(connection: &quinn::Connection, bytes: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = tokio::time::timeout(DEADLINE, connection.open_bi())
        .await
        .expect("the stream must not hang")
        .expect("open the stream");
    tokio::time::timeout(DEADLINE, send.write_all(bytes))
        .await
        .expect("the request must not hang")
        .expect("write the request");
    let mut echoed = vec![0u8; bytes.len()];
    tokio::time::timeout(DEADLINE, recv.read_exact(&mut echoed))
        .await
        .expect("the answer must not hang")
        .expect("read the answer");
    echoed
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
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            // The trait method, not quinn's inherent
                            // one: quinn's returns its own error type.
                            match AsyncReadExt::read(&mut recv, &mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if send.write_all(&buf[..n]).await.is_err() {
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

/// An endpoint on a socket the caller bound itself.
fn bind_owned(addr: SocketAddr, cert: &QuicCert) -> quinn::Endpoint {
    let socket = UdpSocket::bind(addr).unwrap();
    let addr = socket.local_addr().unwrap();
    bind_endpoint_with_socket(addr, socket, cert).unwrap()
}

/// The endpoint serves the tunnel's traffic: the client's handshake
/// completes, the fingerprint it reports is the certificate's, and a
/// stream carries bytes in both directions.
#[tokio::test]
async fn an_endpoint_on_a_caller_bound_socket_carries_a_stream() {
    let cert = certificate();
    let endpoint = bind_owned(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &cert);
    let addr = endpoint.local_addr().unwrap();
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
    tokio::time::timeout(DEADLINE, stream.write_all(b"ping"))
        .await
        .expect("the request must not hang")
        .expect("write the request");
    let mut echoed = [0u8; 4];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut echoed))
        .await
        .expect("the answer must not hang")
        .expect("read the answer");
    assert_eq!(&echoed, b"ping");
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

/// A QUIC client that dials the gateway from a chosen source port.
///
/// The kernel picks the socket that receives a connection out of a
/// reuseport group by the connection's 4-tuple hash, so a test that
/// wants both sockets of the group to serve a connection has to vary
/// the source port. The crate's own client picks its own.
#[cfg(unix)]
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
#[cfg(unix)]
async fn dial(endpoint: &quinn::Endpoint, addr: SocketAddr) -> quinn::Connection {
    let connecting = endpoint
        .connect(addr, SERVER_NAME)
        .expect("dial the gateway");
    tokio::time::timeout(DEADLINE, connecting)
        .await
        .expect("the handshake must not hang")
        .expect("the handshake must succeed")
}

/// A UDP socket with `SO_REUSEPORT` set, bound to `addr`.
///
/// The option has to be set before the bind — that is the whole point
/// of the caller's socket: the crate binds the socket internally, so
/// it cannot set the option itself.
#[cfg(unix)]
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
/// The kernel picks the socket that receives a connection out of the
/// group by the hash of the connection's 4-tuple, so the two sockets
/// share the connections and neither starves.
///
/// A connection that was already up when the second socket joined is
/// **not** guaranteed to keep it: the group's socket array grew, and
/// the flow hash now picks between the two sockets — a flow whose hash
/// lands on the socket that joined is delivered to an endpoint that
/// knows nothing about it. That is the kernel's behaviour and not
/// something the crate can change, so the test asserts what the group
/// does guarantee: both sockets serve connections, and the group
/// loses none.
#[cfg(unix)]
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
    let mut clients = Vec::new();
    let endpoint = client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20000),
        &pins,
    );
    let connection = dial(&endpoint, addr).await;
    assert_eq!(round_trip(&connection, b"ping").await, b"ping");
    clients.push((endpoint, connection));

    // The incoming generation takes the same address the same way.
    let socket = reuse_port_socket(addr).unwrap();
    let second = bind_endpoint_with_socket(addr, socket, &cert).unwrap();
    let second_count = Arc::new(AtomicUsize::new(0));
    serve(second, second_count.clone());

    // Both sockets of the group serve connections: the kernel spreads
    // them over the group, and which socket gets a given connection is
    // not fixed.
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

    // The group loses nothing: every connection a client opened came
    // up on one of the two endpoints.
    assert!(
        wait_for(DEADLINE, || {
            first_count.load(Ordering::SeqCst) + second_count.load(Ordering::SeqCst)
                == clients.len()
        })
        .await,
        "every connection must be accepted by one of the two endpoints"
    );

    // The group carries live traffic: a connection that comes up after
    // the join is served, whichever socket of the group it lands on.
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20064);
    let endpoint = client_endpoint(source, &pins);
    let connection = dial(&endpoint, addr).await;
    assert_eq!(round_trip(&connection, b"ping").await, b"ping");
}
