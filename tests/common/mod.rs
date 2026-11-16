//! Shared helpers for the integration tests.
//!
//! Every helper here is a **test gateway**: the other end of a tunnel,
//! speaking the same protocol the real gateway speaks.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use pangolin_tun::{
    QuicCert, TunnelRole, WsRole, WsUpgradeRequest, YamuxTunnel, bind_endpoint,
    read_ws_upgrade_request, tunnel_over_websocket, wrap_websocket, write_ws_accept_response,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// The longest a test waits for something that should happen at once.
pub const DEADLINE: Duration = Duration::from_secs(15);

/// A backend that echoes every byte it receives.
///
/// It stands in for the service the tunnel reaches on the operator's
/// side of the network.
pub async fn echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
            stream.flush().await.unwrap();
        }
    });
    (port, handle)
}

/// A test gateway that speaks the WebSocket/TCP transport.
///
/// The gateway answers the upgrade request and hands the caller the
/// parsed request and the yamux tunnel it runs on. Both arrive once
/// the client has connected — the helper does not wait for that, so
/// the caller can start the client first.
pub struct WsGateway {
    /// The address the client dials.
    pub addr: String,
    /// The upgrade request the client sent.
    pub request: oneshot::Receiver<WsUpgradeRequest>,
    /// The tunnel the gateway serves.
    pub tunnel: oneshot::Receiver<YamuxTunnel>,
}

/// Bind a WebSocket/TCP test gateway.
pub async fn ws_gateway() -> WsGateway {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (request_tx, request) = oneshot::channel();
    let (tunnel_tx, tunnel) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_ws_upgrade_request(&mut stream).await.unwrap();
        let key = request.sec_websocket_key.clone().unwrap();
        write_ws_accept_response(&mut stream, &key).await.unwrap();
        let ws = wrap_websocket(stream, WsRole::Server);
        let tunnel = tunnel_over_websocket(ws, TunnelRole::Server);
        let _ = request_tx.send(request);
        let _ = tunnel_tx.send(tunnel);
        // The session lives on until the tunnel is dropped.
        std::future::pending::<()>().await;
    });
    WsGateway {
        addr,
        request,
        tunnel,
    }
}

/// A test gateway that speaks the QUIC transport.
pub struct QuicGateway {
    /// The address the client dials.
    pub addr: SocketAddr,
    /// The fingerprint of the gateway's certificate.
    pub fingerprint: String,
    /// The endpoint the connection lives on. It has to outlive the
    /// connection: dropping it tears the connection down.
    pub endpoint: quinn::Endpoint,
}

/// Bind a QUIC test gateway.
pub fn quic_gateway() -> QuicGateway {
    let cert = QuicCert::generate().unwrap();
    let endpoint = bind_endpoint("127.0.0.1:0".parse().unwrap(), &cert).unwrap();
    let addr = endpoint.local_addr().unwrap();
    QuicGateway {
        addr,
        fingerprint: cert.fingerprint,
        endpoint,
    }
}
