//! A client session over the QUIC transport, against a test gateway.

mod common;

use common::{DEADLINE, echo_backend, quic_gateway};
use pangolin_tun::{
    QuicServerTransport, SessionOutcome, TUNNEL_PROTOCOL_VERSION, TransportKind, TransportSelector,
    TunSettings, TunnelClient, TunnelTransport, decode_auth, encode_auth_reply, encode_connect,
    read_crlf_line,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The client's session authenticates on the control stream and
/// relays the gateway's bytes to the backend and back.
#[tokio::test]
async fn a_session_over_quic_relays_the_bytes() {
    let (backend_port, backend) = echo_backend().await;
    let gateway = quic_gateway();

    let dir = tempfile::tempdir().unwrap();
    let client = TunnelClient::new(TunSettings {
        server: gateway.addr.to_string(),
        token: "secret-token".into(),
        name: "office".into(),
        transport: TransportSelector::Quic,
        pin_path: dir.path().join("tun.pins"),
        quic_failure_path: dir.path().join("tun.quic-fail"),
    });

    let fingerprint = gateway.fingerprint.clone();
    let gateway_task = tokio::spawn(async move {
        let incoming = gateway.endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let transport = QuicServerTransport::new(connection);

        // The control stream: the client authenticates on it before
        // the gateway opens any request stream.
        let mut control = transport.accept_stream().await.unwrap().unwrap();
        let line = read_crlf_line(&mut control).await.unwrap();
        let (token, name, version) = decode_auth(line.as_bytes()).unwrap();
        assert_eq!(token, "secret-token");
        assert_eq!(name, "office");
        assert_eq!(version, TUNNEL_PROTOCOL_VERSION);
        control
            .write_all(&encode_auth_reply(Ok(TUNNEL_PROTOCOL_VERSION)))
            .await
            .unwrap();
        control.flush().await.unwrap();

        // The request stream: the gateway writes the CONNECT
        // instruction and reads the client's answer.
        let mut stream = transport.open_stream().await.unwrap();
        stream
            .write_all(&encode_connect("127.0.0.1", backend_port))
            .await
            .unwrap();
        stream.flush().await.unwrap();
        assert_eq!(read_crlf_line(&mut stream).await.unwrap(), "OK");

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        // End the session.
        transport.connection().close(0u32.into(), b"done");
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
        SessionOutcome::Errored { transport, .. } | SessionOutcome::Ended { transport } => {
            assert_eq!(transport, TransportKind::Quic)
        }
        other => panic!("the session must have run over QUIC: {other:?}"),
    }

    // The first contact pinned the gateway's certificate.
    let pins = std::fs::read_to_string(dir.path().join("tun.pins")).unwrap();
    assert!(
        pins.contains(&fingerprint),
        "the gateway's certificate must be pinned: {pins}"
    );
}
