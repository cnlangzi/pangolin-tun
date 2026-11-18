//! A client session over the QUIC transport, against a test gateway.

mod common;

use common::{
    AuthReply, DEADLINE, Gateway, QuicMode, UpgradeReply, client, connect_to, echo_backend,
    round_trip,
};
use pangolin_tun::{SessionOutcome, TransportKind, TransportSelector};

/// The client's session relays the gateway's bytes to the backend and
/// back.
#[tokio::test]
async fn a_session_over_quic_relays_the_bytes() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Quic);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
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
        SessionOutcome::Ended { transport } | SessionOutcome::Errored { transport, .. } => {
            assert_eq!(transport, TransportKind::Quic)
        }
        other => panic!("the session must have run over QUIC: {other:?}"),
    }
}

/// The client serves a first session, the gateway closes it, and the
/// client comes back for a second one — and that session carries a
/// request.
#[tokio::test]
async fn the_client_reconnects_after_the_gateway_closes_the_quic_session() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Quic);

    let run = tokio::spawn(async move { client.run().await });

    let first = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the first session must come up");
    // The gateway closes the session.
    first.close();

    let second = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the client must come back for a second session");

    let mut stream = connect_to(&second.into_session(), "127.0.0.1", backend_port).await;
    let echoed = round_trip(&mut stream, b"ping").await;
    assert_eq!(echoed, b"ping");

    run.abort();
}
