# Trust

## The certificate

The gateway's QUIC endpoint uses a **self-signed** certificate that it
generates itself. The tunnel has no public hostname of its own, and the
operator has no certificate to install on the client, so there is nothing to
validate a chain against.

The certificate is **persisted** next to the gateway's other certificates:

```text
<cert-dir>/tunnel/quic-cert.pem   the certificate, PEM
<cert-dir>/tunnel/quic-key.pem    the private key, PKCS#8, PEM, mode 0600
```

A gateway that regenerated its certificate on every restart would make every
client refuse the next connection — the client pins a fingerprint, not a
certificate request.

## The fingerprint

The fingerprint of a certificate is the SHA-256 of its DER encoding, in
lower-case hex — 64 characters. It identifies the certificate, not the key:
re-issuing a certificate with the same key produces a different fingerprint,
which is what we want — the operator has to re-pin deliberately.

Both ends log the fingerprint. The client logs the one the gateway presented.

## The pin store

The client trusts the gateway **on first use**. The pin file holds the
fingerprints it trusts, one per line:

```text
# Pangolin tunnel — trusted gateway certificate fingerprints.
# One SHA-256 fingerprint (lower-case hex) per line.
# Delete a line to stop trusting that gateway; add a line to trust another one.
3f9a…c1
8b21…04
```

- Lines that start with `#` are comments, and empty lines are ignored, so an
  operator can annotate the file.
- The file holds a **list**, not a single value: a deployment with several
  gateway nodes — each with its own generated certificate — works without
  the operator copying certificates between nodes.
- The fingerprints are compared case-insensitively; the file is written in
  lower case.
- The file is written **atomically**: the list goes into a temporary file
  next to it and is renamed over it. A crash can therefore not leave an
  empty pin file behind — and an empty file reads as "first contact", which
  would re-arm trust on first use.

A missing pin file is an **empty** list — the trust-on-first-use starting
point, not an error.

## The verdict

For every presented certificate the store returns one of three verdicts:

| Verdict | When | What happens |
| --- | --- | --- |
| `Pin` | the list is empty | the certificate is accepted and the fingerprint is pinned and persisted |
| `Accepted` | the fingerprint is in the list | the certificate is accepted |
| `Refused` | the fingerprint is not in the list | the connection is refused |

A refusal names the pinned fingerprints **and** the presented one, and it
says how to re-pin:

```text
the gateway's QUIC certificate is not trusted: it presented the fingerprint bb…,
but this tun only trusts the fingerprint aa…. To trust the new certificate,
remove the stale fingerprint(s) from /var/lib/pangolin/tun.pins and reconnect
— the tun then pins the new one.
```

## Re-pinning

A gateway whose certificate changed is repaired through the pin store — no
hand-editing of the file required:

```rust
let pins = PinStore::open("/var/lib/pangolin/tun.pins")?;

// Remove one stale fingerprint and persist the change. Returns
// whether the fingerprint was in the list.
pins.remove("aa…")?;

// Or drop every fingerprint and persist the empty list, so the
// next connection pins again.
pins.clear()?;
```

## The weak spot

The first contact is the weak point of any trust-on-first-use scheme: a
middleman present at that moment would be pinned instead of the gateway.

Two things narrow the window:

- the client logs the fingerprint the gateway presented, so the operator can
  compare the client's log with the gateway's own log;
- the QUIC handshake returns the presented fingerprint to the caller, so a
  caller can compare it against one it received out of band — a fingerprint
  the operator read from the gateway host, or one a provisioning system
  carries.

## What is *not* checked

- The certificate **chain** is not validated — the certificate is self-signed
  by design.
- The **hostname** is not validated — the tunnel has no public hostname. The
  name presented in the TLS handshake exists only to satisfy the handshake.
- The **signature** *is* checked. The fingerprint identifies the certificate;
  the signature check proves the peer holds the private key that belongs to
  it. Without it, anyone with a copy of the certificate could present it and
  sign the handshake with a key of their own, and the pin would not stop
  them.
