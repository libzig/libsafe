# libsafe

Crypto and handshake primitives for QUIC security paths.

## Overview

`libsafe` provides reusable security building blocks for both:

- **QUIC-over-TLS** (standard TLS handshake and key schedule)
- **QUIC-over-SSH** (SSH-oriented key exchange and host-key workflows)

It focuses on primitives and helpers, not full application protocol state machines.

## Included Areas

- `src/tls/*` - TLS handshake, key schedule, context
- `src/crypto/*` - AEAD, key derivation, header protection
- `src/ssh/*` - X25519, Ed25519, host key/signature blobs, SSH/QUIC secret derivation

## Build and Test

```bash
make build
make test
```

## Docs

- See `docs/` for package documentation and notes.
- If `docs/` is currently sparse, it is the canonical place for upcoming docs.

## Version

- Current package version: `0.0.6`
