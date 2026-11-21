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

The client waits **10 seconds** for that answer. A gateway that accepts the
connection but never answers would otherwise hang the client forever — and the
reconnect loop with it.

The `Sec-WebSocket-Key` is 16 random bytes, base64-encoded. The
`Sec-WebSocket-Accept` is the RFC 6455 §1.3 derivation of it:
base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")).

A header value that reached the gateway from the wire has its CR and LF
stripped, so a value can never terminate its own line and inject a header.

The WebSocket carries a **yamux** session: the client runs the yamux client,
the gateway runs the yamux server. The gateway opens a yamux stream per
request; the client accepts them.

## The streams of a session

A session carries one stream per request, and every stream of a session ends
the way the session ends. A consumer that copies between a tunnel stream and
a socket has to tell three endings apart:

| The stream ended because | The read returns |
| --- | --- |
| the session died — the transport gave up, the peer went away, or the session saw a go-away | an error of the kind `NotConnected` |
| the peer reset the stream | an error of the kind `ConnectionReset` |
| the peer finished its half of the stream | `Ok(0)` — a clean end-of-file |

The two transports report the same kinds for the same events, so a consumer
needs no per-transport branch.

A clean end-of-file is the peer's goodbye: the bytes that arrived are whole,
and no more are coming. The end of the **session** is a failure: the bytes
that were still to come will never come. A consumer that reads it as an
end-of-file hands a truncated request to its backend and relays a truncated
response to its client — and neither the client nor the tunnel learns that
anything went wrong.

## The fallback policy

The transport is chosen **once per session**.

A client that prefers QUIC attempts it with the five-second handshake
timeout. A gateway's name can resolve to several addresses, and every one of
them is tried — the resolver's order is OS-dependent, and a gateway whose
first address does not answer must not cost a fallback to the unencrypted
transport. When the attempt fails:

- **nothing answered** — UDP is blocked, the address is wrong, the handshake
  timed out — the client falls back to the WebSocket/TCP transport, records
  the time of the failure and skips the QUIC probe for the next **10
  minutes**. A network that blocks UDP therefore does not pay the handshake
  timeout on every reconnect.
- **the certificate is not trusted** — it is not the one the client pinned —
  the client does **not** fall back. The fallback is unencrypted, so falling
  back would hand the bearer token to whoever is presenting the wrong
  certificate.
- **the session was refused** — a bad token, a protocol version mismatch, or
  a session that did not come up after the handshake — the client does
  **not** fall back either. The gateway was reached, and the fallback carries
  the same token in cleartext, for no gain.
- **the peer answered QUIC but refused our protocol** — a TLS alert, or a
  peer that speaks another QUIC version — the client does **not** fall back.
  The peer is not a tunnel gateway, and the fallback would hand the bearer
  token in cleartext to a host that just proved it is not one.

A client that is pinned to one transport never attempts the other.

## Which transport did a session use?

The outcome of a session names the transport that was actually used, so a
session that silently fell back is distinguishable from a QUIC session.
