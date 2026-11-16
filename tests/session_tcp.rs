//! A client session over the WebSocket/TCP transport, against a test
//! gateway.

mod common;

use common::{DEADLINE, echo_backend, ws_gateway};
use pangolin_tun::{
    SessionOutcome, TUNNEL_VERSION_HEADER, TransportKind, TransportSelector, TunSettings,
    TunnelClient, encode_connect, read_crlf_line,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The client's session relays the gateway's bytes to the backend and
/// the backend's bytes back.
#[tokio::test]
async fn a_session_over_the_websocket_transport_relays_the_bytes() {
    let (backend_port, backend) = echo_backend().await;
    let gateway = ws_gateway().await;

    let dir = tempfile::tempdir().unwrap();
    let client = TunnelClient::new(TunSettings {
        server: gateway.addr.clone(),
        token: "secret-token".into(),
        name: "office".into(),
        transport: TransportSelector::Tcp,
        pin_path: dir.path().join("tun.pins"),
        quic_failure_path: dir.path().join("tun.quic-fail"),
    });

    let gateway_task = tokio::spawn(async move {
        let tunnel = gateway.tunnel.await.unwrap();
        let request = gateway.request.await.unwrap();

        // The upgrade request carries the client's bearer token and
        // the protocol version — the fallback transport's only
        // handshake.
        assert_eq!(
            request.authorization.as_deref(),
            Some("Bearer secret-token")
        );
        let version = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(TUNNEL_VERSION_HEADER))
            .map(|(_, value)| value.as_str());
        assert_eq!(version, Some("2"));

        // The gateway opens the stream right away: the client's
        // reader stops at the end of the 101 response, so the
        // stream's first bytes are still in the socket when the
        // client's yamux session picks them up.
        let mut stream = tunnel.open_stream().await.unwrap();
        stream
            .write_all(&encode_connect("127.0.0.1", backend_port))
            .await
            .unwrap();
        stream.flush().await.unwrap();
        assert_eq!(read_crlf_line(&mut stream, 4096).await.unwrap(), "OK");

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        // End the session.
        tunnel.bridge_abort.abort();
    });

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the session must not hang");
    tokio::time::timeout(DEADLINE, gateway_task)
        .await
        .expect("the gateway must not hang")
        .unwrap();
    tokio::time::timeout(DEADLINE, backend)
        .await
        .expect("the backend must not hang")
        .unwrap();

    match outcome {
        SessionOutcome::Ended { transport } => assert_eq!(transport, TransportKind::Tcp),
        other => panic!("the session must have ended over the TCP transport: {other:?}"),
    }
}

/// A target that cannot be reached is answered with `ERR <reason>`,
/// and the gateway turns that into a 502 for the client.
#[tokio::test]
async fn a_target_that_cannot_be_reached_is_answered_with_err() {
    // Port 1 on the loopback interface is not listening.
    let gateway = ws_gateway().await;

    let dir = tempfile::tempdir().unwrap();
    let client = TunnelClient::new(TunSettings {
        server: gateway.addr.clone(),
        token: "secret-token".into(),
        name: "office".into(),
        transport: TransportSelector::Tcp,
        pin_path: dir.path().join("tun.pins"),
        quic_failure_path: dir.path().join("tun.quic-fail"),
    });

    let gateway_task = tokio::spawn(async move {
        let tunnel = gateway.tunnel.await.unwrap();
        let mut stream = tunnel.open_stream().await.unwrap();
        stream
            .write_all(&encode_connect("127.0.0.1", 1))
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let reply = read_crlf_line(&mut stream, 4096).await.unwrap();
        assert!(
            reply.starts_with("ERR "),
            "the client must answer ERR, got {reply:?}"
        );

        tunnel.bridge_abort.abort();
    });

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the session must not hang");
    tokio::time::timeout(DEADLINE, gateway_task)
        .await
        .expect("the gateway must not hang")
        .unwrap();

    match outcome {
        SessionOutcome::Ended { transport } => assert_eq!(transport, TransportKind::Tcp),
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
    let client = TunnelClient::new(TunSettings {
        server: format!("127.0.0.1:{port}"),
        token: "secret-token".into(),
        name: "office".into(),
        transport: TransportSelector::Tcp,
        pin_path: dir.path().join("tun.pins"),
        quic_failure_path: dir.path().join("tun.quic-fail"),
    });

    let outcome = tokio::time::timeout(DEADLINE, client.connect_once())
        .await
        .expect("the connect attempt must not hang");

    match outcome {
        SessionOutcome::NotConnected { error, .. } => {
            assert!(
                matches!(error, pangolin_tun::Error::Unreachable(_)),
                "a gateway that is not there is unreachable: {error}"
            );
        }
        other => panic!("the session must not have been established: {other:?}"),
    }
}
