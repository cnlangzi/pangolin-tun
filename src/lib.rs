//! # pangolin-tun
//!
//! The Pangolin tunnel's wire protocol and its client, as one library.
//!
//! A **tunnel** is the connection between a Pangolin gateway and a
//! client that runs in the operator's own network — a home NAS, an
//! office server, a laptop. The gateway opens a byte stream per
//! request and the client relays those bytes to a backend it can
//! reach but the gateway cannot.
//!
//! ## The protocol
//!
//! A tunnel stream is a **splice**: the gateway writes the client's
//! request bytes into it and the client copies them to the backend
//! socket without interpreting them. The stream starts with a single
//! instruction and then carries nothing but bytes:
//!
//! ```text
//! gateway → client   CONNECT <host>:<port>\r\n
//! client → gateway   OK\r\n            (or ERR <reason>\r\n)
//! gateway ⇄ client   bytes, bytes, bytes…
//! ```
//!
//! The host travels as a **name**: the client resolves it in the
//! operator's own network, so a backend that is only reachable from
//! the client's side works.
//!
//! Two transports carry the protocol:
//!
//! * **QUIC** — the primary transport. One connection per client, one
//!   bidirectional stream per request, encrypted by default. The
//!   client authenticates on a control stream right after the
//!   handshake: `AUTH <token> <name> <protocol-version>`.
//! * **WebSocket over TCP** — the fallback for networks where UDP is
//!   blocked. The token and the protocol version ride in the
//!   WebSocket upgrade request.
//!
//! See `docs/protocol.md`, `docs/transports.md` and `docs/trust.md`
//! for the details an implementer in another language needs.
//!
//! ## The client
//!
//! [`TunnelClient`] takes its settings from the caller, dials the
//! gateway, serves the streams the gateway opens and relays them to
//! their targets:
//!
//! ```no_run
//! # use std::path::PathBuf;
//! # use pangolin_tun::{TunnelClient, TransportSelector, TunSettings};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = TunnelClient::new(TunSettings {
//!     server: "gateway.example.com:8443".into(),
//!     token: "the tun's bearer token".into(),
//!     name: "office".into(),
//!     transport: TransportSelector::Auto,
//!     pin_path: PathBuf::from("/var/lib/pangolin/tun.pins"),
//!     quic_failure_path: PathBuf::from("/var/lib/pangolin/tun.quic-fail"),
//! });
//!
//! let (_shutdown, mut stopped) = tokio::sync::watch::channel(false);
//! tokio::select! {
//!     _ = client.run() => {}
//!     _ = stopped.changed() => {}
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The crate reads no configuration file and consults no environment
//! variable: the `tun.yml` schema and the binary that ships it live
//! in the gateway's repository.
//!
//! ## Errors
//!
//! [`Error`] is the crate's error type. Its `Unreachable`, `Untrusted`
//! and `Refused` variants are what a caller acts on — in particular,
//! only `Unreachable` allows a fallback to the unencrypted transport.
//!
//! ## Logging
//!
//! The crate logs through the `log` crate and configures no logger of
//! its own: the caller installs one.

#![deny(missing_docs)]

pub mod client;
pub mod error;
pub mod settings;
pub mod tunnel;

pub use client::{SessionOutcome, TunnelClient};
pub use error::{Error, Result};
pub use settings::{TransportSelector, TunSettings};
pub use tunnel::pin::{PinState, PinStore, PinVerdict, PinningVerifier};
pub use tunnel::quic::{
    QUIC_CERT_FILE, QUIC_KEY_FILE, QuicBiStream, QuicCert, QuicClientTransport, QuicConnectError,
    QuicHandshake, QuicServerTransport, TUNNEL_ALPN, bind_endpoint, bind_endpoint_with_socket,
    certificate_dir, fingerprint, transport_config,
};
pub use tunnel::ws::{
    TUNNEL_VERSION_HEADER, WsRole, WsUpgradeRequest, YamuxStream, YamuxTunnel, bearer_token,
    build_ws_upgrade_request, compute_ws_accept, generate_ws_key, read_ws_accept_response,
    read_ws_upgrade_request, tunnel_over_websocket, wrap_websocket, write_http_error,
    write_ws_accept_response,
};
pub use tunnel::{
    TUNNEL_PROTOCOL_VERSION, TransportKind, TunnelByteStream, TunnelRole, TunnelStream,
    TunnelTransport, decode_auth, decode_auth_reply, decode_connect, decode_connect_reply,
    encode_auth, encode_auth_reply, encode_connect, encode_connect_reply,
    protocol_version_mismatch, read_crlf_line, relay_bidirectional, serve_tunnel_stream,
};

/// Install the rustls ring crypto provider.
///
/// The crate needs a crypto provider for its QUIC transport, and the
/// call is **idempotent**: a second install is a no-op, so a caller
/// that already installed a provider is fine.
///
/// The crate installs the provider itself before its first TLS use, so
/// a caller never has to. This function is public for the caller that
/// wants it in place before anything else runs.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The provider installation is idempotent: calling it twice must
    /// not panic, and the provider must be in place afterwards.
    #[test]
    fn the_crypto_provider_install_is_idempotent() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
