# pangolin-tun

[![crates.io](https://img.shields.io/crates/v/pangolin-tun.svg)](https://crates.io/crates/pangolin-tun)
[![docs.rs](https://img.shields.io/docsrs/pangolin-tun.svg)](https://docs.rs/pangolin-tun)

`pangolin-tun` is a Rust library that carries the Pangolin tunnel's wire
protocol **and** the tunnel client. Its users are the two ends of a Pangolin
tunnel: the gateway, which accepts inbound traffic and splices it into a
tunnel, and the client, which runs in the operator's own network and relays
those bytes to a backend the gateway cannot reach.

The crate is deliberately small in scope. It holds:

- the **protocol** — the CONNECT instruction, the AUTH line, the
  protocol-version handshake, the transport abstraction and its two
  transports (QUIC and WebSocket/TCP), and the trust-on-first-use pin store;
- the **client** — the byte relay, the reconnect policy and the
  QUIC-to-TCP fallback.

It holds no configuration format and no binary. The `tun.yml` schema and the
`pangolin-tun` binary stay in the gateway's repository, next to each other; a
caller injects plain settings instead.

## The tunnel is a splice

A tunnel stream carries a single instruction and then nothing but bytes:

```text
gateway → client   CONNECT <host>:<port>\r\n
client → gateway   OK\r\n            (or ERR <reason>\r\n)
gateway ⇄ client   bytes, bytes, bytes…
```

The host travels as a **name**: the client resolves it in the operator's own
network, so a backend that is only reachable from the client's side works.

Because the stream carries bytes and nothing else, the client speaks no HTTP.
It never parses a request, never builds one and never buffers a response — so
SSE, WebSocket upgrades and every other protocol feature the gateway owns work
over the tunnel without a counterpart on the client's side.

## The two transports

| Transport | Role | Encrypted | Notes |
| --- | --- | --- | --- |
| QUIC | primary | yes | one connection per client, one bidirectional stream per request |
| WebSocket over TCP | fallback | no | for networks where UDP is blocked |

The transport is chosen once per session. A client that prefers QUIC attempts
it with a five-second handshake timeout; on failure it falls back to the
WebSocket/TCP transport, records the failure and skips the QUIC probe for ten
minutes — so a network that blocks UDP does not pay the timeout on every
reconnect.

A failure that is **not** "the gateway could not be reached" never falls back:
the fallback is unencrypted, so it would hand the bearer token to whoever is
presenting the wrong certificate, or carry a token the gateway already
refused.

## Using the client

The client takes its settings from the caller — it reads no configuration file
and consults no environment variable.

```rust
use std::path::PathBuf;
use pangolin_tun::{TunnelClient, TransportSelector, TunSettings};

let client = TunnelClient::new(TunSettings {
    server: "gateway.example.com:8443".into(),
    token: "the tun's bearer token".into(),
    name: "office".into(),
    transport: TransportSelector::Auto,
    pin_path: PathBuf::from("/var/lib/pangolin/tun.pins"),
    quic_failure_path: PathBuf::from("/var/lib/pangolin/tun.quic-fail"),
});

// `run` never returns: cancel the future to stop the client.
let (_shutdown, mut stopped) = tokio::sync::watch::channel(false);
tokio::select! {
    _ = client.run() => {}
    _ = stopped.changed() => {}
}
```

`connect_once` runs a single connect-and-serve cycle and reports its outcome,
so a caller that drives the reconnect policy itself can:

```rust
match client.connect_once().await {
    SessionOutcome::Ended { transport } => { /* the session ended cleanly */ }
    SessionOutcome::Errored { transport, error } => { /* the session failed */ }
    SessionOutcome::NotConnected { transport, error } => { /* never came up */ }
}
```

The transport is part of the outcome because a session that silently fell back
must be distinguishable from a QUIC session.

## Trust on first use

The gateway's QUIC endpoint uses a self-signed certificate it generates
itself, and the operator has no certificate to install on the client. The
client therefore trusts the gateway **on first use**: the first connection's
certificate fingerprint is pinned in a local file, and every later connection
must present a fingerprint from that list.

The file holds a **list**, so a deployment with several gateway nodes works
without the operator copying certificates between nodes. A changed gateway
certificate is repaired through the pin store:

```rust
let pins = PinStore::open("/var/lib/pangolin/tun.pins")?;
pins.remove("the stale fingerprint")?;   // persist the change
pins.clear()?;                          // or trust whatever comes next
```

The first contact is the weak spot of any trust-on-first-use scheme: a
middleman present at that moment would be pinned instead of the gateway. The
client logs the fingerprint the gateway presented, so the operator can compare
it with the gateway's own log.

See `docs/trust.md` for the details.

## Errors

`Error` is the crate's error type. Its `Unreachable`, `Untrusted` and
`Refused` variants are what a caller acts on — in particular, only
`Unreachable` allows a fallback to the unencrypted transport.

## Building a client in another language

The protocol is documented for an implementer who does not use Rust:

- `docs/protocol.md` — the wire protocol, instruction by instruction
- `docs/transports.md` — the two transports and the fallback policy
- `docs/trust.md` — the certificate and the trust-on-first-use pin store

## License

MIT.
