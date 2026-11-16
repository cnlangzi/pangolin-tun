//! The public surface the crate promises.
//!
//! Every item the protocol and the client need is named here, so a
//! rename that would break a caller fails the build instead of
//! failing downstream.

#![allow(unused_imports)]

use pangolin_tun::{
    // The client's own surface.
    Error,
    PinState,
    // The pin store.
    PinStore,
    PinVerdict,
    PinningVerifier,
    QUIC_CERT_FILE,
    QUIC_KEY_FILE,
    QuicBiStream,
    QuicCert,
    QuicClientTransport,
    QuicConnectError,
    QuicServerTransport,
    Result,
    SessionOutcome,
    TUNNEL_ALPN,
    TUNNEL_PROTOCOL_VERSION,
    TUNNEL_VERSION_HEADER,
    // The transport abstraction.
    TransportKind,
    TransportSelector,
    TunSettings,
    TunnelByteStream,
    TunnelClient,
    TunnelRole,
    TunnelStream,
    TunnelTransport,
    WsRole,
    WsUpgradeRequest,
    // The re-exports the gateway uses.
    YamuxStream,
    YamuxTunnel,
    // The WebSocket/TCP transport.
    bearer_token,
    // The QUIC transports.
    bind_endpoint,
    // The WebSocket handshake helpers.
    build_ws_upgrade_request,
    // The QUIC transport's constants and helpers.
    certificate_dir,
    compute_ws_accept,
    // The AUTH codec.
    decode_auth,
    decode_auth_reply,
    // The pieces a caller needs.
    decode_auth_reply as _decode_auth_reply,
    // The CONNECT codec.
    decode_connect,
    decode_connect_reply,
    encode_auth,
    encode_auth_reply,
    encode_connect,
    encode_connect_reply,
    fingerprint,
    generate_ws_key,
    install_crypto_provider,
    // The protocol-version handshake.
    protocol_version_mismatch,
    read_crlf_line,
    read_ws_accept_response,
    read_ws_upgrade_request,
    // The relay and the client's dialer seam.
    relay_bidirectional,
    serve_tunnel_stream,
    transport_config,
    tunnel_over_websocket,
    wrap_websocket,
    write_http_error,
    write_ws_accept_response,
};

/// The QUIC handshake hands the caller the fingerprint the gateway
/// presented, next to the "newly pinned" flag.
#[test]
fn the_quic_handshake_carries_the_presented_fingerprint() {
    let handshake = pangolin_tun::QuicHandshake {
        fingerprint: "aa".into(),
        newly_pinned: true,
    };
    assert_eq!(handshake.fingerprint, "aa");
    assert!(handshake.newly_pinned);
}

/// The pin store can be maintained programmatically.
#[test]
fn the_pin_store_can_be_maintained_programmatically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tun.pins");
    let pins = PinStore::open(&path).unwrap();
    pins.add("aa").unwrap();
    assert!(pins.remove("aa").unwrap());
    assert!(pins.pins().is_empty());
    pins.add("bb").unwrap();
    pins.clear().unwrap();
    assert!(pins.pins().is_empty());
}
