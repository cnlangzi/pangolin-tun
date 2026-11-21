//! A client session over the WebSocket/TCP transport, against a test
//! gateway.

mod common;

use common::{
    AuthReply, DEADLINE, Gateway, QuicMode, UpgradeReply, client, client_at, connect_to,
    echo_backend, round_trip,
};
use pangolin_tun::{Error, SessionOutcome, TransportKind, TransportSelector};
use tokio::io::AsyncReadExt;

/// The client's session relays the gateway's bytes to the backend and
/// the backend's bytes back.
#[tokio::test]
async fn a_session_over_the_websocket_transport_relays_the_bytes() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang")
        .into_session();

    let mut stream = connect_to(&session, "127.0.0.1", backend_port).await;
    let echoed = round_trip(&mut stream, b"ping").await;
    assert_eq!(echoed, b"ping");

    session.close();
    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");

    match outcome {
        SessionOutcome::Ended { transport } => assert_eq!(transport, TransportKind::Tcp),
        other => panic!("the session must have ended over the TCP transport: {other:?}"),
    }
}

/// A gateway whose session dies while a stream is open reports the
/// death on that stream: the read is an error, not a clean
/// end-of-file.
///
/// A clean end-of-file says "the peer finished sending"; a dead
/// session says "the bytes that were still to come will never come".
/// A gateway that cannot tell the two apart relays a truncated
/// response as if it were a whole one.
#[tokio::test]
async fn a_dead_session_reports_the_death_on_the_open_stream() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang")
        .into_session();

    let mut stream = connect_to(&session, "127.0.0.1", backend_port).await;

    // The gateway's session dies while the stream is open.
    session.close();

    let mut buf = [0u8; 16];
    let err = tokio::time::timeout(DEADLINE, stream.read(&mut buf))
        .await
        .expect("the read must not hang")
        .expect_err("a dead session must not read as an end-of-file");
    assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);
    assert_eq!(err.to_string(), "the tunnel session ended");

    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    match outcome {
        SessionOutcome::Ended { transport } | SessionOutcome::Errored { transport, .. } => {
            assert_eq!(transport, TransportKind::Tcp)
        }
        other => panic!("the session must have ended over the TCP transport: {other:?}"),
    }
}

/// A gateway that is not there at all is an **unreachable** gateway —
/// the one failure the client may recover from by falling back.
#[tokio::test]
async fn a_gateway_that_is_not_there_is_unreachable() {
    // Bind and drop a listener, so the port is almost certainly free.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };

    let dir = tempfile::tempdir().unwrap();
    let client = client_at(
        dir.path(),
        &format!("127.0.0.1:{port}"),
        TransportSelector::Tcp,
    );

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { error, .. } => {
            assert!(
                matches!(error, Error::Unreachable(_)),
                "a gateway that is not there is unreachable: {error}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}

/// The client serves a first session, the gateway closes it, and the
/// client comes back for a second one.
#[tokio::test]
async fn the_client_reconnects_after_the_gateway_closes_the_session() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let task = tokio::spawn(async move { client.run().await });

    let first = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the first session must come up");
    // The gateway closes the session.
    first.tunnel.as_ref().unwrap().bridge_abort.abort();

    let second = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the client must come back for a second session");
    assert!(
        second.tunnel.is_some(),
        "the second session must run on a tunnel"
    );

    task.abort();
}
