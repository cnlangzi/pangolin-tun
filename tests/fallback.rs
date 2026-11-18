//! The transport decision and the fallback policy.
//!
//! The gateway serves both transports on one port number, so a client
//! that falls back opens a TCP connection to the very address its
//! QUIC attempt went to — and the counters see it.

mod common;

use std::time::{Duration, Instant};

use common::{
    AuthReply, DEADLINE, Gateway, QuicMode, TOKEN, UpgradeReply, client, client_at, connect_to,
    echo_backend, round_trip, unix_now,
};
use pangolin_tun::client::QUIC_PROBE_SKIP_SECS;
use pangolin_tun::{Error, SessionOutcome, TransportKind, TransportSelector, TunSettings};

/// With both transports served, the session runs over QUIC.
#[tokio::test]
async fn auto_runs_the_session_over_quic() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Auto);

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
    assert_eq!(
        common::outcome_transport(&outcome),
        Some(TransportKind::Quic)
    );
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

/// A network that blocks UDP costs the handshake timeout and then the
/// session runs over the WebSocket/TCP transport.
#[tokio::test]
async fn auto_falls_back_to_tcp_when_udp_does_not_answer() {
    let gateway = Gateway::bind(QuicMode::Blackhole, AuthReply::Accept, UpgradeReply::Accept).await;
    let (backend_port, _backend) = echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Auto);

    let started = Instant::now();
    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang")
        .into_session();

    // The fallback waits the handshake timeout out: a client that
    // gave up earlier would downgrade a network that only needed a
    // moment.
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(4500),
        "the fallback must not happen before the handshake timeout: {waited:?}"
    );
    assert!(
        waited <= Duration::from_secs(20),
        "the fallback must not take an age: {waited:?}"
    );

    let mut stream = connect_to(&session, "127.0.0.1", backend_port).await;
    let echoed = round_trip(&mut stream, b"ping").await;
    assert_eq!(echoed, b"ping");

    session.close();
    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        common::outcome_transport(&outcome),
        Some(TransportKind::Tcp)
    );

    assert!(
        gateway.udp_datagrams() >= 1,
        "the QUIC attempt must have reached the blackhole"
    );

    // The failure was recorded, so the next session skips the probe.
    let recorded = std::fs::read_to_string(dir.path().join("tun.quic-fail")).unwrap();
    let failed_at: i64 = recorded.trim().parse().unwrap();
    assert!(
        failed_at > 0,
        "the failure record must hold a Unix timestamp: {recorded}"
    );
}

/// A network that blocks UDP must not pay the handshake timeout on
/// every reconnect.
#[tokio::test]
async fn a_recent_quic_failure_skips_the_probe() {
    let gateway = Gateway::bind(QuicMode::Blackhole, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tun.quic-fail"), unix_now().to_string()).unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Auto);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang")
        .into_session();
    session.close();

    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        common::outcome_transport(&outcome),
        Some(TransportKind::Tcp)
    );
    assert_eq!(
        gateway.udp_datagrams(),
        0,
        "the tun must not have probed QUIC at all"
    );
}

/// The skip expires: a network that unblocks UDP is picked up without
/// operator action.
#[tokio::test]
async fn an_expired_quic_failure_probes_again() {
    let gateway = Gateway::bind(QuicMode::Blackhole, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let expired = unix_now() - QUIC_PROBE_SKIP_SECS - 60;
    std::fs::write(dir.path().join("tun.quic-fail"), expired.to_string()).unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Auto);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang")
        .into_session();
    session.close();

    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        common::outcome_transport(&outcome),
        Some(TransportKind::Tcp)
    );
    assert!(
        gateway.udp_datagrams() >= 1,
        "the tun must have probed QUIC again"
    );
}

/// A client pinned to QUIC never falls back: the operator chose the
/// encrypted transport.
#[tokio::test]
async fn a_quic_pinned_client_does_not_fall_back() {
    let gateway = Gateway::bind(QuicMode::Blackhole, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Quic);

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Quic));
            assert!(
                matches!(error, Error::Unreachable(_)),
                "a gateway that does not answer is unreachable: {error}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
    assert_eq!(
        gateway.tcp_connections(),
        0,
        "the tun must not have opened a TCP connection"
    );
}

/// A client pinned to the fallback transport never contacts QUIC.
#[tokio::test]
async fn a_tcp_pinned_client_never_contacts_quic() {
    let gateway = Gateway::bind(QuicMode::Blackhole, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Tcp);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_tcp())
        .await
        .expect("the gateway must not hang")
        .into_session();
    session.close();

    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");
    assert_eq!(
        common::outcome_transport(&outcome),
        Some(TransportKind::Tcp)
    );
    assert_eq!(
        gateway.udp_datagrams(),
        0,
        "the tun must not have contacted the QUIC endpoint"
    );
}

/// A gateway whose certificate is not pinned does not get the bearer
/// token in cleartext: the tun refuses instead of falling back.
#[tokio::test]
async fn an_untrusted_gateway_does_not_fall_back() {
    let gateway = Gateway::bind(QuicMode::Serve, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    let pinned = "a".repeat(64);
    std::fs::write(dir.path().join("tun.pins"), format!("{pinned}\n")).unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Auto);

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
                message.contains(&gateway.fingerprint),
                "the presented fingerprint must be named: {message}"
            );
            assert!(
                message.contains(&pinned),
                "the pinned fingerprint must be named: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
    assert_eq!(
        gateway.quic_connections(),
        1,
        "the tun must have reached the gateway over QUIC"
    );
    assert_eq!(
        gateway.tcp_connections(),
        0,
        "the bearer token must not have travelled in cleartext"
    );
}

/// A gateway that refuses the session was reached: falling back would
/// carry the same token in cleartext, for no gain.
#[tokio::test]
async fn a_refused_session_does_not_fall_back() {
    let gateway = Gateway::bind(
        QuicMode::Serve,
        AuthReply::Refuse("Unauthorized".into()),
        UpgradeReply::Accept,
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Auto);

    let task = tokio::spawn(async move { client.connect_once().await });
    let session = tokio::time::timeout(DEADLINE, gateway.accept_quic())
        .await
        .expect("the gateway must not hang");
    assert_eq!(session.auth.0, TOKEN);

    let outcome = tokio::time::timeout(DEADLINE, task)
        .await
        .expect("the session must not hang")
        .expect("the client must not panic");

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
    assert_eq!(
        gateway.quic_connections(),
        1,
        "the tun must have reached the gateway over QUIC"
    );
    assert_eq!(
        gateway.tcp_connections(),
        0,
        "the tun must not have opened a TCP connection"
    );
}

/// A host that is not a tunnel gateway never receives the bearer
/// token.
///
/// The host answers QUIC but refuses our protocol: the fallback is
/// unencrypted, and falling back would hand the bearer token to a
/// host that just proved it is not the gateway.
#[tokio::test]
async fn a_host_that_is_not_a_tunnel_gateway_never_receives_the_token() {
    let gateway = Gateway::bind(
        QuicMode::Foreign,
        AuthReply::Accept,
        UpgradeReply::Refuse {
            status: 404,
            reason: "Not Found".into(),
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &gateway, TransportSelector::Auto);

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Quic));
            let Error::Refused(message) = error else {
                panic!("the host must have refused the protocol: {error}");
            };
            assert!(
                message.contains("not a tunnel gateway"),
                "the message must say what is wrong: {message}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
    assert_eq!(
        gateway.quic_connections(),
        1,
        "the tun must have reached the host over QUIC"
    );
    assert_eq!(
        gateway.tcp_connections(),
        0,
        "the bearer token must not have travelled in cleartext"
    );
}

/// A pin file that cannot be read stops the QUIC attempt — and the
/// fallback does not happen either.
#[tokio::test]
async fn an_unreadable_pin_file_stops_the_quic_attempt() {
    let gateway = Gateway::bind(QuicMode::Blackhole, AuthReply::Accept, UpgradeReply::Accept).await;
    let dir = tempfile::tempdir().unwrap();
    // The pin file's path points at a directory: it cannot be read.
    let client = pangolin_tun::TunnelClient::new(TunSettings {
        server: gateway.addr.clone(),
        token: TOKEN.to_string(),
        name: common::NAME.to_string(),
        transport: TransportSelector::Auto,
        pin_path: dir.path().to_path_buf(),
        quic_failure_path: dir.path().join("tun.quic-fail"),
    });

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Quic));
            assert!(
                matches!(error, Error::Io(_)),
                "an unreadable pin file is an I/O failure: {error}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
    assert_eq!(
        gateway.tcp_connections(),
        0,
        "the tun must not have opened a TCP connection"
    );
    assert_eq!(
        gateway.udp_datagrams(),
        0,
        "the tun must not have sent a datagram"
    );
}

/// A gateway that is not there at all is unreachable on both
/// transports.
#[tokio::test]
async fn a_gateway_that_is_not_there_is_unreachable_on_both_transports() {
    // Bind and drop a listener, so the port is almost certainly free.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };

    let dir = tempfile::tempdir().unwrap();
    let client = client_at(
        dir.path(),
        &format!("127.0.0.1:{port}"),
        TransportSelector::Auto,
    );

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { transport, error } => {
            assert_eq!(transport, Some(TransportKind::Tcp));
            assert!(
                matches!(error, Error::Unreachable(_)),
                "a gateway that is not there is unreachable: {error}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}
