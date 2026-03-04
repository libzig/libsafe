# libsafe Documentation

## What this package does

`libsafe` provides reusable cryptography and handshake primitives used for QUIC security paths.

It is split into two major tracks:

- TLS-oriented primitives (for QUIC-over-TLS workflows)
- SSH-oriented primitives (for QUIC-over-SSH workflows)

This package focuses on crypto and handshake building blocks. It is not an application protocol runtime.

## Module layout

- `src/crypto/`
  - AEAD packet protection helpers
  - key derivation helpers
  - header protection helpers
- `src/tls/`
  - handshake structures and processing helpers
  - key schedule helpers
  - TLS context handling
- `src/ssh/`
  - X25519 ECDH helpers (`ecdh.zig`)
  - Ed25519 signing/verification (`signature.zig`)
  - SSH host key and signature blob helpers (`hostkey.zig`)
  - SSH->QUIC secret derivation (`secret_derivation.zig`)
- `src/engine.zig`
  - engine-level handshake abstraction and integration surface

## TLS path notes

TLS-oriented APIs handle the cryptographic pieces required by QUIC TLS flows:

- handshake parsing/creation helpers
- key schedule transitions
- QUIC key material extraction/expansion
- ALPN and transport-parameter-facing primitives

## SSH path notes

SSH-oriented APIs cover the cryptographic core used by SSH-flavored QUIC setups:

- ephemeral X25519 key agreement
- Ed25519 signing and verification
- strict SSH host key/signature blob encode/decode
- SHA256 host-key fingerprint generation
- session secret derivation from SSH exchange outputs

## How to use it

1. Import the package module in your Zig build.
2. Choose TLS or SSH path helpers based on your handshake model.
3. Use packet/key helpers from `src/crypto/` for protection operations.
4. Keep protocol state machines in your higher-level package; use `libsafe` for crypto mechanics.

## Build and test

```bash
make build
make test
```

## Security and implementation guidance

- Prefer strict decoding paths for SSH blobs.
- Keep private key material in bounded scopes.
- Zeroize sensitive temporary buffers where possible.
- Keep derivation labels explicit and stable.
- Add deterministic vectors for every new primitive API.

## Version

- `0.0.6`
