//! Trust on first use.
//!
//! The tun pins the gateway's certificate fingerprint on the first
//! contact and refuses every certificate that is not on the list.

mod common;

use common::{AuthReply, DEADLINE, Gateway, QuicMode, UpgradeReply, client, outcome_transport};
use pangolin_tun::{
    Error, PinStore, QuicClientTransport, SessionOutcome, TransportKind, TransportSelector,
};

/// The first contact pins the gateway's certificate.
#[tokio::test]
async fn the_first_contact_pins_the_certificate() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let pin_path = dir.path().join("tun.pins");

    let pins = PinStore::open(&pin_path).unwrap();
    assert!(
        pins.pins().is_empty(),
        "the first contact has nothing pinned yet"
    );

    let address: std::net::SocketAddr = gateway.addr.parse().unwrap();
    let (_transport, handshake) = QuicClientTransport::connect(address, "127.0.0.1", &pins)
        .await
        .expect("the first contact must be accepted");

    assert!(
        handshake.newly_pinned,
        "the first contact pins the certificate"
    );
    assert_eq!(handshake.fingerprint, gateway.fingerprint);
    assert_eq!(pins.pins(), vec![gateway.fingerprint.clone()]);

    let written = std::fs::read_to_string(&pin_path).unwrap();
    assert!(
        written.contains(&gateway.fingerprint),
        "the pin file must hold the fingerprint: {written}"
    );
}

/// A pinned certificate is accepted again.
#[tokio::test]
async fn a_pinned_certificate_is_accepted_again() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let tun = client(dir.path(), &gateway, TransportSelector::Quic);

    let task = tokio::spawn(async move { tun.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the gateway must not hang");
    session.close();
    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        outcome_transport(&outcome),
        Some(TransportKind::Quic),
        "the first session must have run over QUIC: {outcome:?}"
    );

    // The second session against the same gateway is accepted.
    let tun = client(dir.path(), &gateway, TransportSelector::Quic);
    let task = tokio::spawn(async move { tun.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the gateway must not hang");
    session.close();
    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        outcome_transport(&outcome),
        Some(TransportKind::Quic),
        "the second session must have run over QUIC: {outcome:?}"
    );
    assert_eq!(
        gateway.quic_connections(),
        2,
        "both sessions must have reached the gateway over QUIC"
    );

    // The pin file still holds exactly that one fingerprint.
    let pins = PinStore::open(dir.path().join("tun.pins")).unwrap();
    assert_eq!(pins.pins(), vec![gateway.fingerprint.clone()]);
}

/// A gateway that presents a different certificate is refused, and the
/// message names both fingerprints and says how to re-pin.
#[tokio::test]
async fn a_changed_certificate_is_refused() {
    let first = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let tun = client(dir.path(), &first, TransportSelector::Quic);

    let task = tokio::spawn(async move { tun.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, first.accept_quic())
        .await
        .expect("the gateway must not hang");
    session.close();
    tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");

    // A second gateway presents a different certificate.
    let second = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    assert_ne!(first.fingerprint, second.fingerprint);

    let tun = client(dir.path(), &second, TransportSelector::Quic);
    let outcome = tokio::time::timeout(DEADLINE, tun.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Quic));
            let Error::Untrusted(message) = error else {
                panic!("the gateway must be untrusted: {error}");
            };
            assert!(
                message.contains(&first.fingerprint),
                "the pinned fingerprint must be named: {message}"
            );
            assert!(
                message.contains(&second.fingerprint),
                "the presented fingerprint must be named: {message}"
            );
            assert!(
                message.contains("pin"),
                "the message must say how to re-pin: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}

/// The stale fingerprint goes, and the next connection pins the new
/// certificate.
#[tokio::test]
async fn a_removed_fingerprint_lets_the_new_certificate_be_pinned() {
    let first = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let tun = client(dir.path(), &first, TransportSelector::Quic);

    let task = tokio::spawn(async move { tun.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, first.accept_quic())
        .await
        .expect("the gateway must not hang");
    session.close();
    tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");

    // A second gateway presents a different certificate.
    let second = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;

    // The stale fingerprint is removed by hand — that is what the
    // refusal message tells the operator to do.
    let pins = PinStore::open(dir.path().join("tun.pins")).unwrap();
    assert!(
        pins.remove(&first.fingerprint).unwrap(),
        "the stale fingerprint must be on the list"
    );

    let tun = client(dir.path(), &second, TransportSelector::Quic);
    let task = tokio::spawn(async move { tun.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, second.accept_quic())
        .await
        .expect("the gateway must not hang");
    session.close();
    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        outcome_transport(&outcome),
        Some(TransportKind::Quic),
        "the session must have run over QUIC: {outcome:?}"
    );
    assert_eq!(
        second.quic_connections(),
        1,
        "the tun must have reached the new gateway over QUIC"
    );

    let pins = PinStore::open(dir.path().join("tun.pins")).unwrap();
    assert_eq!(pins.pins(), vec![second.fingerprint.clone()]);
}

/// The list holds several fingerprints, so a deployment with several
/// gateway nodes works without copying certificates between nodes.
#[tokio::test]
async fn the_pin_list_accepts_several_gateways() {
    let first = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let second = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    assert_ne!(first.fingerprint, second.fingerprint);

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("tun.pins"),
        format!("{}\n{}\n", first.fingerprint, second.fingerprint),
    )
    .unwrap();

    for gateway in [&first, &second] {
        let tun = client(dir.path(), gateway, TransportSelector::Quic);
        let task = tokio::spawn(async move { tun.connect_once().await });
        let session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
            .await
            .expect("the gateway must not hang");
        session.close();
        let outcome = tokio::time::timeout(DEADLINE, task)
            .await
            .expect("the session must not hang")
            .expect("the client must not panic");
        assert_eq!(
            outcome_transport(&outcome),
            Some(TransportKind::Quic),
            "the session must have run over QUIC: {outcome:?}"
        );
        assert_eq!(
            gateway.quic_connections(),
            1,
            "the tun must have reached the gateway over QUIC"
        );
    }
}
