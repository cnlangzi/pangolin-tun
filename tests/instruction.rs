//! The CONNECT instruction's boundaries.
//!
//! The instruction is one line: a host that carries a line break, a
//! target that does not resolve, and an instruction that is longer
//! than the line bound each have their own outcome — and none of them
//! takes the session down.

mod common;

use common::{
    backend_at, connect_to, each_transport, echo_backend, open_raw_stream, open_stream, round_trip,
};
use pangolin_tun::{TunnelStream, encode_connect, read_crlf_line};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Read a stream to its end, whatever ends it.
///
/// A stream the tun gave up on is reset rather than closed, so the
/// read fails — but the bytes it carried are what a test is after.
async fn drain(stream: &mut TunnelStream) -> String {
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes).await;
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A backend that listens only on the IPv6 loopback is reached
/// through the tun.
///
/// The CONNECT instruction carries an IPv6 literal bracketed
/// (`[::1]:8080`); the brackets are URL syntax and the tun strips them
/// before it resolves the host.
#[tokio::test]
async fn a_backend_on_the_ipv6_loopback_is_reached() {
    // The IPv6 loopback is a property of the machine, not of the
    // protocol: a machine without one has nothing to test.
    if TcpListener::bind("[::1]:0").await.is_err() {
        eprintln!("note: this machine has no IPv6 loopback — the scenario is skipped");
        return;
    }

    each_transport(|wired| async move {
        let (port, _backend) = backend_at("[::1]:0", |mut stream| async move {
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            stream.flush().await.unwrap();
        })
        .await
        .expect("bind the IPv6 backend");

        let mut stream = connect_to(&wired.session, "[::1]", port).await;
        let echoed = round_trip(&mut stream, b"ping").await;
        assert_eq!(
            echoed, b"ping",
            "the tun must reach the IPv6 backend over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// A CONNECT instruction whose host carries a line break is refused,
/// and no second line reaches the tun's stream.
///
/// The gateway emits the deliberately malformed instruction rather
/// than smuggling a second line into the tun's stream.
#[tokio::test]
async fn a_connect_instruction_with_a_line_break_in_the_host_is_refused() {
    each_transport(|wired| async move {
        let bytes = encode_connect("evil\r\nCONNECT other:1", 80);
        let mut stream = open_raw_stream(&wired.session, &bytes).await;

        let reply = read_crlf_line(&mut stream).await.unwrap();
        assert!(
            reply.starts_with("ERR "),
            "the tun must refuse the instruction over {}: {reply:?}",
            wired.kind
        );
        let rest = drain(&mut stream).await;
        assert!(
            !format!("{reply}\n{rest}")
                .lines()
                .any(|line| line.starts_with("CONNECT")),
            "the stream must carry no CONNECT line of its own over {}: {reply:?} {rest:?}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// A target whose name does not resolve is answered with `ERR`.
#[tokio::test]
async fn a_target_that_does_not_resolve_is_answered_with_err() {
    each_transport(|wired| async move {
        let mut stream = open_stream(&wired.session, "no-such-host.invalid", 80).await;
        let reply = read_crlf_line(&mut stream).await.unwrap();
        assert!(
            reply.starts_with("ERR "),
            "the tun must answer ERR over {}, got {reply:?}",
            wired.kind
        );
        let reason = reply.trim_start_matches("ERR ");
        assert!(
            !reason.contains('\r') && !reason.contains('\n'),
            "the reason must be one line over {}: {reason:?}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// An instruction longer than the line bound is a protocol error that
/// costs the stream, not the session.
#[tokio::test]
async fn an_instruction_longer_than_the_line_bound_costs_the_stream_not_the_session() {
    each_transport(|wired| async move {
        // More than 4096 bytes, and no terminator.
        let mut stream = open_raw_stream(&wired.session, &vec![b'x'; 4097]).await;

        let text = drain(&mut stream).await;
        assert!(
            !text.contains("OK"),
            "the stream must not be answered with OK over {}: {text:?}",
            wired.kind
        );
        assert!(
            !text.contains("ERR"),
            "the stream must not be answered with ERR over {}: {text:?}",
            wired.kind
        );

        // The session survives: the next request is served.
        let (port, _backend) = echo_backend().await;
        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        let echoed = round_trip(&mut stream, b"ping").await;
        assert_eq!(
            echoed, b"ping",
            "the session must survive the over-long instruction over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}
