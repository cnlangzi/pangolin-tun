//! The protocol traffic the tunnel carries.
//!
//! The tun speaks no HTTP at all: it copies the bytes, so every
//! protocol feature the gateway owns works over the tunnel without a
//! counterpart on the tun's side.

mod common;

use std::sync::Arc;

use common::{backend, connect_to, each_transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

/// A GET without a body — the request a health check sends.
const GET: &[u8] = b"GET /healthz?verbose=1 HTTP/1.1\r\n\
Host: backend.internal\r\n\
User-Agent: pangolin-tun-test\r\n\
\r\n";

/// A full HTTP/1.1 request reaches the backend byte-exact, and the
/// backend's response comes back byte-exact.
#[tokio::test]
async fn an_http_request_and_its_response_survive_the_splice() {
    each_transport(|wired| async move {
        let body = r#"{"hello":"world"}"#;
        let request = format!(
            "POST /api/v1/items?limit=10&offset=20 HTTP/1.1\r\n\
             Host: backend.internal\r\n\
             Content-Type: application/json\r\n\
             X-Request-Id: abc-123\r\n\
             Accept: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len()
        )
        .into_bytes();
        let response = b"HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Set-Cookie: a=1\r\n\
Set-Cookie: b=2\r\n\
Content-Length: 2\r\n\
\r\n\
ok";

        let (tx, mut rx) = mpsc::unbounded_channel();
        let expected = request.clone();
        let answer = response.to_vec();
        let (port, _backend) = backend(move |mut stream| {
            let expected = expected.clone();
            let answer = answer.clone();
            let tx = tx.clone();
            async move {
                let mut got = vec![0u8; expected.len()];
                stream.read_exact(&mut got).await.unwrap();
                let _ = tx.send(got);
                stream.write_all(&answer).await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        stream.write_all(&request).await.unwrap();
        stream.flush().await.unwrap();

        let received = common::received(&mut rx).await;
        assert_eq!(
            received, request,
            "the request must reach the backend byte-exact over {}",
            wired.kind
        );

        let mut answered = vec![0u8; response.len()];
        stream.read_exact(&mut answered).await.unwrap();
        assert_eq!(
            answered, response,
            "the response must come back byte-exact over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// A GET without a `Content-Length` and without a body survives the
/// splice byte-exact.
#[tokio::test]
async fn a_get_without_a_content_length_survives_the_splice() {
    each_transport(|wired| async move {
        let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

        let (tx, mut rx) = mpsc::unbounded_channel();
        let expected = GET.to_vec();
        let answer = response.to_vec();
        let (port, _backend) = backend(move |mut stream| {
            let expected = expected.clone();
            let answer = answer.clone();
            let tx = tx.clone();
            async move {
                let mut got = vec![0u8; expected.len()];
                stream.read_exact(&mut got).await.unwrap();
                let _ = tx.send(got);
                stream.write_all(&answer).await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        stream.write_all(GET).await.unwrap();
        stream.flush().await.unwrap();

        let received = common::received(&mut rx).await;
        assert_eq!(
            received, GET,
            "the request must reach the backend byte-exact over {}",
            wired.kind
        );

        let mut answered = vec![0u8; response.len()];
        stream.read_exact(&mut answered).await.unwrap();
        assert_eq!(
            answered, response,
            "the response must come back byte-exact over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// The response is not buffered: the gateway sees the first event
/// before the backend produces the next one.
#[tokio::test]
async fn an_endless_response_arrives_incrementally() {
    each_transport(|wired| async move {
        let release = Arc::new(Notify::new());
        let signalled = release.clone();
        let (port, _backend) = backend(move |mut stream| {
            let signalled = signalled.clone();
            async move {
                stream.write_all(b"event-1\n").await.unwrap();
                stream.flush().await.unwrap();
                // The backend waits: the gateway must see the first
                // event before the second one is produced.
                signalled.notified().await;
                stream.write_all(b"event-2\n").await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        let mut first = [0u8; 8];
        tokio::time::timeout(common::DEADLINE, stream.read_exact(&mut first))
            .await
            .unwrap_or_else(|_| panic!("the first event must arrive over {}", wired.kind))
            .unwrap();
        assert_eq!(&first, b"event-1\n");

        // Now the backend may produce the next event.
        release.notify_one();
        let mut second = [0u8; 8];
        stream.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"event-2\n");

        wired.outcome().await;
    })
    .await;
}

/// The bytes of an HTTP/1.1 upgrade request, the `101` answer and a
/// binary payload all survive the splice byte-exact.
#[tokio::test]
async fn a_websocket_upgrade_and_its_payload_survive_the_splice() {
    each_transport(|wired| async move {
        let request = b"GET /chat HTTP/1.1\r\n\
Host: backend.internal\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
\r\n";
        let payload: Vec<u8> = (0u8..=255).collect();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let head = request.to_vec();
        let accepted = response.to_vec();
        let (port, _backend) = backend(move |mut stream| {
            let head = head.clone();
            let accepted = accepted.clone();
            let tx = tx.clone();
            async move {
                let mut got = vec![0u8; head.len()];
                stream.read_exact(&mut got).await.unwrap();
                let _ = tx.send(got);
                stream.write_all(&accepted).await.unwrap();
                stream.flush().await.unwrap();

                let mut frame = vec![0u8; 256];
                stream.read_exact(&mut frame).await.unwrap();
                let _ = tx.send(frame.clone());
                stream.write_all(&frame).await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        stream.write_all(request).await.unwrap();
        stream.flush().await.unwrap();

        let received = common::received(&mut rx).await;
        assert_eq!(
            received, request,
            "the upgrade request must reach the backend byte-exact over {}",
            wired.kind
        );

        let mut answered = vec![0u8; response.len()];
        stream.read_exact(&mut answered).await.unwrap();
        assert_eq!(
            answered, response,
            "the 101 answer must come back byte-exact over {}",
            wired.kind
        );

        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();

        let echoed = common::received(&mut rx).await;
        assert_eq!(
            echoed, payload,
            "the payload must reach the backend byte-exact over {}",
            wired.kind
        );

        let mut answer = vec![0u8; payload.len()];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(
            answer, payload,
            "the payload must come back byte-exact over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}

/// A backend that answers `500` reaches the gateway as those bytes —
/// the tun does not turn it into anything else.
#[tokio::test]
async fn the_backend_error_status_is_relayed_verbatim() {
    each_transport(|wired| async move {
        let response = b"HTTP/1.1 500 Internal Server Error\r\n\
Content-Type: text/plain\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\
\r\n";

        let (tx, mut rx) = mpsc::unbounded_channel();
        let expected = GET.to_vec();
        let answer = response.to_vec();
        let (port, _backend) = backend(move |mut stream| {
            let expected = expected.clone();
            let answer = answer.clone();
            let tx = tx.clone();
            async move {
                let mut got = vec![0u8; expected.len()];
                stream.read_exact(&mut got).await.unwrap();
                let _ = tx.send(got);
                stream.write_all(&answer).await.unwrap();
                stream.flush().await.unwrap();
            }
        })
        .await;

        let mut stream = connect_to(&wired.session, "127.0.0.1", port).await;
        stream.write_all(GET).await.unwrap();
        stream.flush().await.unwrap();

        let received = common::received(&mut rx).await;
        assert_eq!(received, GET);

        let mut answered = vec![0u8; response.len()];
        stream.read_exact(&mut answered).await.unwrap();
        assert_eq!(
            answered, response,
            "the error status must be relayed verbatim over {}",
            wired.kind
        );

        wired.outcome().await;
    })
    .await;
}
