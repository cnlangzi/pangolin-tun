//! The byte splice.
//!
//! The tun copies the gateway's bytes to the backend and the
//! backend's bytes back, without interpreting them.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{backend, connect_to, each_transport, echo_backend, open_stream, round_trip};
use pangolin_tun::read_crlf_line;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Bytes that are not HTTP at all survive the splice unchanged in
/// both directions.
#[tokio::test]
async fn the_bytes_survive_the_splice() {
    each_transport(|wired| async move {
        let (port, _backend) = echo_backend().await;
        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;

        let payload: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let echoed = round_trip(&mut stream, &payload).await;
        assert_eq!(
            echoed, payload,
            "the bytes must survive the splice over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// One session carries several streams at once, and each of them
/// reaches its own backend connection.
#[tokio::test]
async fn one_session_carries_several_concurrent_requests() {
    each_transport(|wired| async move {
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        let (port, _backend) = backend(move |mut stream| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                    stream.flush().await.unwrap();
                }
            }
        })
        .await;

        let mut streams = Vec::new();
        for index in 0..3 {
            let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
            let request = format!("request-{index}");
            stream.write_all(request.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            streams.push((request, stream));
        }

        for (request, mut stream) in streams {
            let mut answer = vec![0u8; request.len()];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(
                answer,
                request.as_bytes(),
                "each stream must come back with its own answer over {}",
                wired.kind
            );
        }

        assert_eq!(
            connections.load(Ordering::SeqCst),
            3,
            "each request must reach its own backend connection over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// The gateway ends its write side; the backend answers afterwards and
/// the response still reaches the gateway.
#[tokio::test]
async fn a_response_that_arrives_after_the_request_ended_still_comes_through() {
    each_transport(|wired| async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (port, _backend) = backend(move |mut stream| {
            let tx = tx.clone();
            async move {
                // The backend answers only once it saw the end of the
                // request.
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                let _ = tx.send(request);
                stream.write_all(b"pong").await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        // The gateway ends its write side.
        stream.shutdown().await.unwrap();

        let request = common::received(&mut rx).await;
        assert_eq!(request, b"ping");

        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.unwrap();
        assert_eq!(
            answer, b"pong",
            "the late response must still come through over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// The backend ends its response direction, and the bytes the
/// gateway writes after the answer still reach it.
///
/// The request direction is a separate half of the splice: a backend
/// that answered and hung up must not cost the gateway the bytes it
/// still had to send.
#[tokio::test]
async fn the_request_direction_stays_open_after_the_backend_ended_its_response() {
    each_transport(|wired| async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (port, _backend) = backend(move |mut stream| {
            let tx = tx.clone();
            async move {
                // The backend answers, ends its response direction and
                // keeps reading.
                stream.write_all(b"pong").await.unwrap();
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await.unwrap();
                let _ = tx.send(rest);
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        // The gateway reads the answer.
        let mut answer = vec![0u8; 4];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"pong");

        // ... and then writes what it still had to say.
        stream.write_all(b"more").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();

        let received = common::received(&mut rx).await;
        assert_eq!(
            received, b"more",
            "the bytes written after the answer must reach the backend over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// One mebibyte travels in each direction and arrives intact.
#[tokio::test]
async fn a_large_payload_survives_the_tunnel() {
    const SIZE: usize = 1024 * 1024;

    each_transport(|wired| async move {
        let payload: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (port, _backend) = backend(move |mut stream| {
            let tx = tx.clone();
            async move {
                let mut got = vec![0u8; SIZE];
                stream.read_exact(&mut got).await.unwrap();
                let _ = tx.send(got.clone());
                stream.write_all(&got).await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let stream = connect_to(&wired.session, "127.0.0.1", port).await;
        // The payload is written and read at the same time: a
        // transport that buffers the whole response would stall here.
        let (mut reader, mut writer) = tokio::io::split(stream);
        let to_send = payload.clone();
        let sending = tokio::spawn(async move {
            writer.write_all(&to_send).await.unwrap();
            writer.flush().await.unwrap();
        });
        let mut echoed = vec![0u8; SIZE];
        reader.read_exact(&mut echoed).await.unwrap();
        sending.await.unwrap();

        assert_eq!(
            echoed, payload,
            "the response must arrive intact over {}",
            wired.kind
        );
        let received = common::received(&mut rx).await;
        assert_eq!(
            received, payload,
            "the request must arrive intact over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// A target that cannot be reached is answered with `ERR <reason>` on
/// the stream, and the reason is on one line.
#[tokio::test]
async fn an_unreachable_target_is_answered_with_err() {
    each_transport(|wired| async move {
        // Port 1 on the loopback interface is not listening.
        let mut stream = open_stream(&wired.session, "127.0.0.1", 1).await;
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

/// The host in the CONNECT instruction is a **name**: the tun resolves
/// it in the operator's own network.
#[tokio::test]
async fn the_target_is_reached_by_name() {
    each_transport(|wired| async move {
        let (port, _backend) = echo_backend().await;
        let mut stream = connect_to(&wired.session, "localhost", port).await;
        let echoed = round_trip(&mut stream, b"ping").await;
        assert_eq!(
            echoed, b"ping",
            "the tun must resolve the name itself over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}
