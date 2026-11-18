//! The session's life cycle.
//!
//! A client that starts before the gateway exists, a session that
//! stays silent for longer than the idle timeout, and a backend that
//! dies in the middle of a request.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{
    AuthReply, DEADLINE, LONG_DEADLINE, QuicMode, UpgradeReply, backend, client_at, connect_to,
    each_transport, echo_backend, round_trip,
};
use pangolin_tun::{TransportKind, TransportSelector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A client that starts before the gateway exists connects once the
/// gateway binds, and carries a request.
///
/// The transport the session lands on is not asserted: the first QUIC
/// attempt happened before the gateway was there, so that cycle may
/// have fallen back to the unencrypted transport.
#[tokio::test]
async fn a_client_that_starts_before_the_gateway_connects_once_it_binds() {
    // The address is reserved and released: the gateway takes it
    // seven seconds later.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client_at(dir.path(), &addr.to_string(), TransportSelector::Auto);

    let run = tokio::spawn(async move { client.run().await });

    // The gateway is not there yet.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let gateway = common::Gateway::bind_at(
        addr,
        QuicMode::Serve,
        AuthReply::Accept,
        UpgradeReply::Accept,
    )
    .await;

    // The client comes back for the gateway that is there now.
    let session = tokio::time::timeout(LONG_DEADLINE, gateway.accept_any())
        .await
        .expect("the client must come back for the gateway");

    let mut stream = connect_to(&session, "127.0.0.1", backend_port).await;
    let echoed = round_trip(&mut stream, b"ping").await;
    assert_eq!(echoed, b"ping");

    session.close();
    run.abort();
}

/// A session that is silent for longer than the idle timeout still
/// carries traffic.
///
/// The QUIC transport keeps the connection warm with a keep-alive
/// every ten seconds and closes it after thirty seconds of silence: a
/// session that stays silent for thirty-five seconds must still be
/// usable.
#[tokio::test]
async fn a_session_that_stays_silent_still_carries_traffic() {
    let gateway =
        common::Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client_at(dir.path(), &gateway.addr, TransportSelector::Quic);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the gateway must not hang")
        .into_session();

    // The session says nothing for longer than the idle timeout.
    tokio::time::sleep(Duration::from_secs(35)).await;

    let mut stream = connect_to(&session, "127.0.0.1", backend_port).await;
    let echoed = round_trip(&mut stream, b"ping").await;
    assert_eq!(
        echoed, b"ping",
        "the silent session must still carry traffic"
    );

    session.close();
    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        common::outcome_transport(&outcome),
        Some(TransportKind::Quic)
    );
    assert_eq!(
        gateway.quic_connections(),
        1,
        "the silent session must have survived — it must not have been replaced"
    );
}

/// A backend that closes the connection in the middle of a request
/// does not take the tunnel down.
///
/// The stream ends, the session stays up, and the next request the
/// gateway opens reaches the backend and its answer comes back.
#[tokio::test]
async fn a_backend_that_dies_mid_request_does_not_take_the_tunnel_down() {
    each_transport(|wired| async move {
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        let (port, _backend) = backend(move |mut stream| {
            let counted = counted.clone();
            async move {
                let first = counted.fetch_add(1, Ordering::SeqCst) == 0;
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).await.unwrap();
                if first {
                    // The backend dies in the middle of the request.
                    drop(stream);
                    return;
                }
                stream.write_all(&buf[..n]).await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        // The gateway's stream ends: the backend is gone.
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert!(
            rest.is_empty(),
            "the stream must end without bytes over {}: {rest:?}",
            wired.kind
        );

        // The session is still up: the next request reaches the
        // backend and its answer comes back.
        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        let echoed = round_trip(&mut stream, b"ping").await;
        assert_eq!(
            echoed, b"ping",
            "the session must survive a dead backend over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}
