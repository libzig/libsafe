# libsafe Documentation

This is the practical documentation for `libsafe`.

It focuses on:
- what the library is and is not
- architecture boundaries in the `libzig` stack
- how to pick and use TLS/SSH APIs
- security behavior and invariants
- testing, integration, and troubleshooting

---

## 1) What libsafe is

`libsafe` is the shared crypto/security core for the stack.

It provides reusable primitives and validation helpers for:
- TLS 1.3-oriented handshake and key schedule behavior
- SSH-oriented key exchange, signatures, host-key handling, and derivation
- common QUIC crypto helpers (AEAD, key derivation, header protection)

`libsafe` is not a transport runtime. It does not own QUIC packet flow, congestion, loss recovery, stream scheduling, or application protocol behavior.

---

## 2) Stack boundaries

Current intended ownership:
- `libsafe`: crypto primitives + handshake/security helpers
- `libfast`: QUIC transport/state machine execution
- `liblink`: SSH protocol/application behavior
- `libflux`: HTTP/3 + WebTransport behavior

Rule of thumb:
- if it is cryptographic correctness or handshake validation, it likely belongs in `libsafe`
- if it is packet/stream/transport orchestration, it belongs upstream (usually `libfast`)

The boundary classifier for TLS-facing API surfaces lives in `src/tls/contract.zig`.

---

## 3) Public module map

Top-level exports are in `src/libsafe.zig`.

### 3.1 Common crypto (`src/crypto`)

- `aead.zig`
  - AEAD algorithms and encrypt/decrypt wrappers
- `keys.zig`
  - HKDF/label-based key material derivation helpers
- `header_protection.zig`
  - QUIC header protection helpers
- `crypto.zig`
  - higher-level context wiring around the primitives above

### 3.2 TLS (`src/tls`)

- `handshake.zig`
  - TLS hello encode/decode and extension parsing helpers
- `key_schedule.zig`
  - transcript hashing and secret derivation chain
- `tls_context.zig`
  - stateful TLS helper context used by adapters/callers
- `auth.zig`
  - certificate validity and hostname/client-auth validation helpers
- `diagnostics.zig`
  - structured handshake diagnostics and key-log line helper
- `extensions.zig`
  - ALPN extension wire parsing and offer-matching helpers
- `finished.zig`
  - Finished verify-data computation/verification helper
- `policy.zig`
  - cipher suite selection and cipher->hash mapping helpers
- `interop.zig`
  - reusable TLS interop test hook entry points
- `matrix.zig`
  - matrix-style aggregation helper for interop regression sets
- `contract.zig`
  - API-role classification and transport-boundary checks

### 3.3 SSH (`src/ssh`)

- `ecdh.zig`
  - X25519 keypair generation and ECDH exchange
- `signature.zig`
  - Ed25519 sign/verify + keypair helpers
- `hostkey.zig`
  - strict SSH hostkey/signature blob handling + fingerprinting
- `secret_derivation.zig`
  - SSH->QUIC secrets and exporter-style derivation helpers
- `kex_methods.zig`
  - KEX negotiation/validation and transcript assembly helpers
- `auth_crypto.zig`
  - auth-signature verification wrappers with structured errors
- `rekey.zig`
  - key lifecycle and rekey helpers
- `algorithms.zig`
  - algorithm identifiers and selection extension points
- `obfuscation.zig`
  - optional SSH envelope obfuscation helpers

### 3.4 Engine/adapters

- `engine.zig`
  - generic handshake engine vtable abstraction
- `adapters/libfast_tls_context_adapter.zig`
  - `TlsContext` adapter for libfast-facing integration

---

## 4) TLS usage guide

### 4.1 Minimal context flow

```zig
const std = @import("std");
const libsafe = @import("libsafe");

pub fn tls_flow(allocator: std.mem.Allocator) !void {
    var client = libsafe.tls_context.TlsContext.init(allocator, true);
    defer client.deinit();

    const ch = try client.startClientHandshake("example.com");
    defer allocator.free(ch);

    // ... obtain server hello bytes from caller/runtime ...
    // try client.processServerHello(server_hello_bytes);
    // try client.completeHandshake("shared-secret");
}
```

### 4.2 Certificate/hostname checks

Use `libsafe.tls_auth` for deterministic validation logic independent of transport runtime.

Typical pattern:
- parse certificates upstream
- map parsed metadata into `tls_auth.CertificateMetadata`
- call `verify_server_certificate(...)`

### 4.3 Diagnostics and key logging

`libsafe.tls_diagnostics` provides:
- redacted diagnostics snapshots (fingerprints, not raw secrets)
- key-log line emitter helper for external tooling

`TlsContext.diagnosticsSnapshot(...)` exposes a convenience snapshot for current state.

---

## 5) SSH usage guide

### 5.1 Sign and verify

```zig
const std = @import("std");
const libsafe = @import("libsafe");

pub fn ssh_sign_verify() !void {
    var prng = std.Random.DefaultPrng.init(1);
    const kp = libsafe.ssh_signature.KeyPair.generate(prng.random());

    const msg = "payload";
    const sig = try libsafe.ssh_signature.sign(msg, &kp.private_key);
    const ok = libsafe.ssh_signature.verifyEd25519(msg, &sig, &kp.public_key);
    try std.testing.expect(ok);
}
```

### 5.2 Host key blob strictness

For untrusted input, use strict/validator APIs from `ssh_hostkey`.
These enforce:
- exact algorithm match (`ssh-ed25519`)
- exact length checks
- trailing-data rejection (strict path)
- oversized-field limits

### 5.3 Rekey and lifecycle helpers

Use `ssh_rekey` for:
- threshold checks (bytes/time)
- generation-scoped traffic key updates
- secure owned secret buffers with zeroize-on-deinit behavior

---

## 6) Interop regression hooks (TLS)

`libsafe.tls_interop` and `libsafe.tls_matrix` are built to be consumed by higher layers and CI.

Current helpers include:
- single-case `ServerHello` processing outcomes
- full handshake case execution
- matrix aggregation with mismatch counting
- curated badssl-like subset coverage in unit tests

Local helper script:

```bash
./tools/tls_badssl_subset.sh
```

---

## 7) Security model and invariants

The library emphasizes:
- strict parser behavior for attacker-controlled inputs
- deterministic negative paths (errors are explicit and test-covered)
- bounded ownership and clear free/deinit behavior
- secret zeroization in sensitive temporary buffers
- deterministic vectors and regression tests for derivation/signing flows

When adding code, keep these invariants stable.

---

## 8) Build and test commands

Core:

```bash
make test
make build
```

Extra confidence:

```bash
make test-dual-mode
./tools/tls_badssl_subset.sh
```

Repository gate baseline (recommended before dependency bumps):
1. `libsafe`: `make test && make build`
2. `libfast`: `make test && make build`
3. `liblink`: `make test && make build`
4. `libflux`: `make test && make build`

---

## 9) Troubleshooting

### Build/test fails in TLS context changes

Check these first:
- `src/tls/tls_context.zig`
- `src/tls/extensions.zig`
- `src/tls/policy.zig`
- `src/tls/finished.zig`

Most failures are from state transition assumptions or ALPN/extension wire checks.

### Unexpected ALPN mismatch

Verify:
- offered ALPN wire is well-formed
- selected ALPN exists in the offered list
- server-side preference ordering in `tls_policy`

### Unexpected SSH signature/hostkey rejection

Verify:
- strict blob parser expectations (algorithm + lengths + trailing bytes)
- caller is not passing non-canonical/extra payload
- algorithm feature/selection assumptions in `ssh/algorithms.zig`

---

## 10) Extension rules for contributors

When adding features:
1. Keep module tests close to implementation.
2. Add at least one malformed-input negative test for new parsers.
3. Add deterministic tests for new derivation/signature logic.
4. Preserve transport boundaries (no QUIC runtime duplication in `libsafe`).
5. Keep commit messages one-line title only.

When changing TLS behavior:
1. run `make test`
2. run `./tools/tls_badssl_subset.sh`
3. run `make build`
4. run cross-repo gate if dependency/API changes are involved

---

## 11) Version and source of truth

- package version is tracked in `build.zig.zon`
- public API surface is exported from `src/libsafe.zig`
- architecture and implementation roadmap lives in `PLAN.md`
