# The two transports

The protocol is the same on both transports. Only the way the bytes travel,
and the way the client authenticates, differ.

| | QUIC | WebSocket over TCP |
| --- | --- | --- |
| Role | primary | fallback |
| Encryption | always | none of its own |
| Session | one QUIC connection | one WebSocket carrying a yamux session |
| Streams | one QUIC bidirectional stream per request | one yamux stream per request |
| Authentication | `AUTH` line on a control stream | `Authorization: Bearer` header |
| Protocol version | in the `AUTH` line | in the `X-Pangolin-Tunnel-Version` header |

## QUIC

The primary transport. One connection per client, one bidirectional stream per
request. It removes the nested-TCP penalty of the WebSocket fallback and
encrypts the tunnel by default — the bearer token and the operator's traffic
no longer cross the network in cleartext.

- The ALPN is `pangolin-tunnel/1`. It identifies the tunnel protocol, so a
  client cannot be talked into a different QUIC service on the same host, and
  a host that is not a tunnel gateway refuses the handshake instead of
  misreading the bytes.
- The client opens a **control stream** right after the handshake and writes
  `AUTH <token> <name> <protocol-version>` on it. The gateway validates the
  token before it opens any request stream on that connection.
- The client waits **5 seconds** for the handshake to complete. A network
  that silently drops UDP never produces an error — the timeout is what
  saves the connection.
- The client waits **10 seconds** for the gateway's answer to the `AUTH`
  line. A gateway that accepts the connection but never answers would
  otherwise hang the session forever.
- The transport keeps the connection warm with a keep-alive every 10 seconds
  and closes it after 30 seconds of silence.

## WebSocket over TCP

The fallback, for networks where UDP is blocked.

The client opens a TCP connection and sends a WebSocket upgrade request:

```text
GET /tunnel?name=<name> HTTP/1.1\r\n
Host: <gateway>\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: <16 random bytes, base64>\r\n
Sec-WebSocket-Version: 13\r\n
Authorization: Bearer <token>\r\n
X-Pangolin-Tunnel-Version: 2\r\n
\r\n
```

The gateway answers with `101 Switching Protocols` and a matching
`Sec-WebSocket-Accept`, or with an HTTP error — a wrong token and a protocol
version mismatch are both refused here.

The `Sec-WebSocket-Key` is 16 random bytes, base64-encoded. The
`Sec-WebSocket-Accept` is the RFC 6455 §1.3 derivation of it:
base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")).

A header value that reached the gateway from the wire has its CR and LF
stripped, so a value can never terminate its own line and inject a header.

The WebSocket carries a **yamux** session: the client runs the yamux client,
the gateway runs the yamux server. The gateway opens a yamux stream per
request; the client accepts them.

## The fallback policy

The transport is chosen **once per session**.

A client that prefers QUIC attempts it with the five-second handshake
timeout. When the attempt fails:

- **the gateway could not be reached** — UDP is blocked, the address is
  wrong, the handshake timed out — the client falls back to the WebSocket/TCP
  transport, records the time of the failure and skips the QUIC probe for the
  next **10 minutes**. A network that blocks UDP therefore does not pay the
  handshake timeout on every reconnect.
- **the gateway could not be trusted** — its certificate is not the one the
  client pinned — the client does **not** fall back. The fallback is
  unencrypted, so falling back would hand the bearer token to whoever is
  presenting the wrong certificate.
- **the gateway refused the session** — a bad token, a protocol version
  mismatch — the client does **not** fall back either. The fallback carries
  the same refused token in cleartext, for no gain.

A client that is pinned to one transport never attempts the other.

## Which transport did a session use?

The outcome of a session names the transport that was actually used, so a
session that silently fell back is distinguishable from a QUIC session.
