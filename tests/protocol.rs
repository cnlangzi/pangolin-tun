//! The wire protocol, exercised through the crate's public API.
//!
//! These tests use nothing but the exported items — they are what an
//! implementer in another language builds against.

use pangolin_tun::{
    TUNNEL_PROTOCOL_VERSION, decode_auth, decode_auth_reply, decode_connect, decode_connect_reply,
    encode_auth, encode_auth_reply, encode_connect, encode_connect_reply,
    protocol_version_mismatch,
};

/// The CONNECT instruction is one line, so the client can read it
/// before it has connected to anything.
#[test]
fn the_connect_instruction_roundtrips() {
    let bytes = encode_connect("backend.internal", 8080);
    assert_eq!(bytes, b"CONNECT backend.internal:8080\r\n");
    let (host, port) = decode_connect(&bytes).unwrap();
    assert_eq!(host, "backend.internal");
    assert_eq!(port, 8080);
}

/// The client's answer is `OK` or `ERR <reason>`; the reason survives
/// the round-trip.
#[test]
fn the_connect_reply_roundtrips() {
    assert_eq!(
        decode_connect_reply(&encode_connect_reply(Ok(()))).unwrap(),
        Ok(())
    );
    assert_eq!(
        decode_connect_reply(&encode_connect_reply(Err("no route to host"))).unwrap(),
        Err("no route to host".to_string())
    );
}

/// The AUTH line carries the token, the client's name and the
/// protocol version.
#[test]
fn the_auth_line_roundtrips() {
    let bytes = encode_auth("secret-token", "office", TUNNEL_PROTOCOL_VERSION);
    let (token, name, version) = decode_auth(&bytes).unwrap();
    assert_eq!(token, "secret-token");
    assert_eq!(name, "office");
    assert_eq!(version, TUNNEL_PROTOCOL_VERSION);
}

/// The gateway's answer carries the protocol version, so a client can
/// refuse a gateway that speaks a different one.
#[test]
fn the_auth_reply_roundtrips() {
    let bytes = encode_auth_reply(Ok(TUNNEL_PROTOCOL_VERSION));
    assert_eq!(
        decode_auth_reply(&bytes).unwrap(),
        Ok(TUNNEL_PROTOCOL_VERSION)
    );
    assert_eq!(
        decode_auth_reply(&encode_auth_reply(Err("bad token"))).unwrap(),
        Err("bad token".to_string())
    );
}

/// A version mismatch names **both** versions, so the operator can
/// tell which side is behind.
#[test]
fn the_version_mismatch_names_both_versions() {
    let message = protocol_version_mismatch(TUNNEL_PROTOCOL_VERSION, 1);
    assert!(
        message.contains(&format!("v{TUNNEL_PROTOCOL_VERSION}")),
        "{message}"
    );
    assert!(message.contains("v1"), "{message}");
}
