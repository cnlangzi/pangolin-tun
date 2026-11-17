//! The handshake on both transports.
//!
//! QUIC authenticates on a control stream right after the handshake;
//! the WebSocket/TCP fallback carries the token and the protocol
//! version in its upgrade request.

mod common;

use common::{
    AuthReply, DEADLINE, Gateway, LONG_DEADLINE, NAME, QuicMode, TOKEN, UpgradeReply, client,
};
use pangolin_tun::{
    Error, SessionOutcome, TUNNEL_PROTOCOL_VERSION, TUNNEL_VERSION_HEADER, TransportKind,
    TransportSelector, protocol_version_mismatch,
};

/// The AUTH line the tun writes on the control stream carries the
/// token, the tun's name and the protocol version.
#[tokio::test]
async fn the_quic_auth_line_carries_the_token_the_name_and_the_version() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Quic);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the gateway must not hang");

    assert_eq!(session.auth.0, TOKEN);
    assert_eq!(session.auth.1, NAME);
    assert_eq!(session.auth.2, TUNNEL_PROTOCOL_VERSION);

    session.close();
    tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
}

/// A gateway that refuses the AUTH line ends the attempt: the session
/// was never established.
#[tokio::test]
async fn a_quic_gateway_that_refuses_the_auth_line_is_not_connected() {
    let gateway = Gateway::bind(
        QuicMode::Serve,
        AuthReply::Refuse("Unauthorized".into()),
        UpgradeReply::Accept,
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Quic);

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Quic));
            let Error::Refused(message) = error else {
                panic!("the gateway must have refused the session: {error}");
            };
            assert!(
                message.contains("Unauthorized"),
                "the gateway's reason must be carried: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}

/// A gateway that speaks another protocol version is refused, and the
/// message names both versions.
///
/// The crate reports the mismatch as `Untrusted`, because the tun
/// cannot tell a version mismatch from a wrong certificate until it
/// has read the gateway's answer — and either way it must not fall
/// back to the unencrypted transport.
#[tokio::test]
async fn a_quic_gateway_that_answers_another_version_is_refused() {
    let gateway = Gateway::bind(
        QuicMode::Serve,
        AuthReply::Version(TUNNEL_PROTOCOL_VERSION + 1),
        UpgradeReply::Accept,
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Quic);

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Quic));
            let Error::Untrusted(message) = error else {
                panic!("the gateway must be untrusted: {error}");
            };
            assert!(
                message.contains(&format!("v{TUNNEL_PROTOCOL_VERSION}")),
                "the tun's own version must be named: {message}"
            );
            assert!(
                message.contains(&format!("v{}", TUNNEL_PROTOCOL_VERSION + 1)),
                "the gateway's version must be named: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}

/// A gateway that accepts the QUIC connection and never answers the
/// AUTH line would otherwise hang the client's session forever.
#[tokio::test]
async fn a_quic_gateway_that_answers_the_auth_line_too_late_is_refused() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Silent, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Quic);

    let task = tokio::spawn(async move { client.connect_once().await });
    // The session is held for the whole attempt: dropping it would
    // close the connection and the client would see an end of file
    // instead of the timeout.
    let _session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the gateway must not hang");

    let outcome = tokio::time::timeout(LONG_DEADLINE, task)
        .await
        .expect("the connect attempt must not hang")
        .expect("the client must not panic");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Quic));
            let Error::Refused(message) = error else {
                panic!("the gateway must have refused the session: {error}");
            };
            assert!(
                message.contains("did not answer"),
                "the message must say the gateway stayed silent: {message}"
            );
            // The crate's AUTH reply timeout is ten seconds; the
            // message names it so the operator knows how long the tun
            // waited.
            assert!(
                message.contains("10s"),
                "the message must name the timeout: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}

/// The upgrade request carries the bearer token, the tun's name and
/// the protocol version.
#[tokio::test]
async fn the_upgrade_request_carries_the_token_the_name_and_the_version() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang");

    assert_eq!(
        session.upgrade.authorization.as_deref(),
        Some("Bearer secret-token")
    );
    assert_eq!(session.upgrade.target, "/tunnel?name=office");
    let version = session
        .upgrade
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(TUNNEL_VERSION_HEADER))
        .map(|(_, value)| value.as_str());
    let expected = TUNNEL_PROTOCOL_VERSION.to_string();
    assert_eq!(version, Some(expected.as_str()));

    session.tunnel.as_ref().unwrap().bridge_abort.abort();
    tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
}

/// A gateway that refuses the upgrade ends the attempt: the session
/// was never established.
#[tokio::test]
async fn a_gateway_that_refuses_the_upgrade_is_not_connected() {
    let gateway = Gateway::bind(
        QuicMode::Serve,
        AuthReply::Accept,
        UpgradeReply::Refuse {
            status: 401,
            reason: "Unauthorized".into(),
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Tcp));
            let Error::Refused(message) = error else {
                panic!("the gateway must have refused the session: {error}");
            };
            assert!(
                message.contains("Unauthorized"),
                "the gateway's reason must be carried: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
    assert_eq!(
        gateway.tcp_connections(),
        1,
        "the tun must have dialled the gateway"
    );
}

/// A gateway that speaks another protocol version refuses the
/// upgrade, and the message names both versions.
#[tokio::test]
async fn a_gateway_that_speaks_another_version_is_refused() {
    let gateway = Gateway::bind(
        QuicMode::Serve,
        AuthReply::Accept,
        UpgradeReply::Refuse {
            status: 400,
            reason: protocol_version_mismatch(TUNNEL_PROTOCOL_VERSION, TUNNEL_PROTOCOL_VERSION + 1),
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Tcp));
            let Error::Refused(message) = error else {
                panic!("the gateway must have refused the session: {error}");
            };
            assert!(
                message.contains(&format!("v{TUNNEL_PROTOCOL_VERSION}")),
                "the tun's own version must be named: {message}"
            );
            assert!(
                message.contains(&format!("v{}", TUNNEL_PROTOCOL_VERSION + 1)),
                "the gateway's version must be named: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}

/// A gateway that accepts the WebSocket connection and never answers
/// the upgrade request would otherwise hang the client's session
/// forever.
#[tokio::test]
async fn a_gateway_that_never_answers_the_upgrade_is_refused() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Silent).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let task = tokio::spawn(async move { client.connect_once().await });
    // The session is held for the whole attempt: dropping it would
    // close the connection and the client would see an end of file
    // instead of the timeout.
    let _session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang");

    let outcome = tokio::time::timeout(LONG_DEADLINE, task)
        .await
        .expect("the connect attempt must not hang")
        .expect("the client must not panic");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Tcp));
            let Error::Refused(message) = error else {
                panic!("the gateway must have refused the session: {error}");
            };
            assert!(
                message.contains("did not answer"),
                "the message must say the gateway stayed silent: {message}"
            );
            // The crate's upgrade reply timeout is ten seconds; the
            // message names it so the operator knows how long the tun
            // waited.
            assert!(
                message.contains("10s"),
                "the message must name the timeout: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}

/// The client does not get stuck on a gateway that says nothing: the
/// reconnect loop takes over and the client comes back.
#[tokio::test]
async fn a_gateway_that_never_answers_the_upgrade_does_not_stick_the_client() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Silent).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let run = tokio::spawn(async move { client.run().await });
    // The client waits out the upgrade timeout, backs off and comes
    // back: the gateway accepts a second connection.
    let _first = tokio::time::timeout(LONG_DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang");
    tokio::time::timeout(LONG_DEADLINE, gateway.accept_tcp())
        .await
        .expect("the client must come back for a second attempt");

    assert!(
        gateway.tcp_connections() >= 2,
        "the client must have dialled the gateway again: {}",
        gateway.tcp_connections()
    );
    run.abort();
    let _ = run.await;
}
