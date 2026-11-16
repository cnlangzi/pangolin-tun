# The tunnel protocol

The wire contract between a Pangolin gateway and a tunnel client. It is
deliberately small: a tunnel stream carries one instruction, one answer and
then nothing but bytes.

Everything here is ASCII. Every line ends with `\r\n`.

## The shape of a tunnel

```text
                 raw HTTP/1.1 bytes (or WS frame bytes)
                           │
                           ▼
                 yamux::Stream (one per request/conn)
                           │
                           ▼
                 yamux::Session
                           │
                           ▼
              the transport (QUIC stream, or a WS)
```

A **session** is one connection between the two ends. It carries many
**streams**; each stream is one request.

The gateway opens a stream per request; the client accepts the streams the
gateway opened. The two ends are symmetric — yamux and QUIC are symmetric
transports — so both directions exist on both.

## The CONNECT instruction

The gateway writes this at the start of every tunnel stream:

```text
CONNECT <host>:<port>\r\n
```

- The host is a **name**, not an address. The client resolves it in the
  operator's own network, so a backend that is only reachable from the
  client's side works.
- An IPv6 literal arrives bracketed (`[::1]:8080`). The brackets are URL
  syntax, not part of the host — strip them before resolving.
- The port is a decimal number in `1..=65535`.
- A host that contains CR, LF or NUL cannot be encoded safely. The gateway
  emits a deliberately malformed instruction (`CONNECT <invalid-host>\r\n`)
  rather than smuggling a second line into the client's stream, and the
  client refuses it.

The instruction is a single line, so the client reads it before it has
connected to anything.

## The CONNECT reply

The client answers the instruction with exactly one line:

```text
OK\r\n
```

or, when the target could not be reached,

```text
ERR <reason>\r\n
```

`<reason>` is a single line of free text. The gateway turns an `ERR` into a
502 for the client that made the original request.

## The byte stream

After the `OK`, the stream carries nothing but bytes, in both directions,
until both sides are done.

The relay half-closes explicitly: when one direction reaches end-of-file,
only the *write* half of the other side is shut down, and the other
direction keeps running. A response that arrives after the request is
complete therefore still reaches the client.

## The AUTH line

The client authenticates once per session, before the gateway opens any
request stream on it. Over QUIC it writes the line on a **control stream** —
a stream it opens itself, immediately after the handshake:

```text
AUTH <token> <name> <protocol-version>\r\n
```

- `<token>` is the bearer token the gateway validates against its `tun`
  table.
- `<name>` is the client's registered name.
- `<protocol-version>` is a decimal number, currently `2`.

The gateway answers on the same stream:

```text
OK <protocol-version>\r\n
```

or

```text
ERR <reason>\r\n
```

The gateway's answer carries **its** protocol version, so the client can
refuse a gateway that speaks a different one even when the client's own line
was accepted.

Over the WebSocket/TCP transport there is no control stream: the token and
the protocol version ride in the upgrade request. See
[transports.md](transports.md).

## The protocol version

`TUNNEL_PROTOCOL_VERSION` is `2`. It travels in its own handshake on each
transport:

- as the `X-Pangolin-Tunnel-Version` header of the WebSocket upgrade request,
- in the `AUTH` control line over QUIC.

An end that sees a different number refuses the connection with a message
naming **both** versions, so the operator can tell which side is behind:

```text
tunnel protocol version mismatch: this side speaks v2, the peer speaks v1 - upgrade the tun and the gateway together
```

## Bounds

- A control or instruction line is at most 4096 bytes, terminator included.
  A longer line is a protocol error.
- The `OK` / `ERR` reply is read **one byte at a time**. The gateway reads
  the client's reply off the *same* stream that later carries the response,
  so a buffered read would swallow the first response bytes.

## Errors

The wire protocol has no error frame. A failure is either an `ERR` line on
the stream, or the stream (and with it the session) ending.
