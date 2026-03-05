# Changelog

## [0.0.8] - 2026-03-05

### <!-- 0 -->⛰️  Features

- Add TLS handshake matrix aggregation hooks
- Add TLS API boundary contract module
- Add full TLS interop handshake case hooks
- Add TLS interop case hooks
- Add TLS diagnostics and keylog callback helpers
- Add TLS auth validation helpers and diagnostics credit

### <!-- 2 -->🚜 Refactor

- Extract TLS cipher policy helpers
- Extract TLS finished verification helper
- Extract TLS extension parsing helpers
- Unify TLS ALPN wire validation helpers
- Split TLS context handshake phase helpers

### <!-- 6 -->🧪 Testing

- Add a test for badssl-like matrix stability

## [0.0.7] - 2026-03-04

### <!-- 0 -->⛰️  Features

- Add generation-scoped SSH traffic key updates
- Add hostkey-blob auth signature verification
- Add SSH algorithm agility extension points
- Add SSH rekey lifecycle utilities
- Add SSH auth signature crypto utilities
- Canonicalize SSH mpint secret derivation
- Add SSH KEX guards and exporter secret API
- Harden SSH hostkey blob parsing

### <!-- 3 -->📚 Documentation

- Add comprehensive documentation

### <!-- 6 -->🧪 Testing

- Add SSH ECDH deterministic derivation checks
- Add SSH label expansion boundary coverage
- Expand SSH hostkey validator and fingerprint checks
- Tighten SSH algorithm selection edge cases
- Expand SSH KEX negotiation and hash guards
- Add SSH rekey context and immutability checks
- Expand hostkey-based SSH auth failure coverage
- Strengthen TLS key schedule determinism checks
- Add TLS handshake encoding edge guards
- Cover TLS out-of-order extension handling
- Guard TLS client state on bad server hello
- Guard TLS server hello ALPN preconditions
- Validate TLS processServerHello field retention
- Verify TLS server cipher preference selection
- Add TLS context invalid state matrix
- Guard TLS local transport parameter validation
- Add TLS finished verification checks
- Expand engine vtable forwarding coverage
- Add TLS handshake version and size guards
- Add TLS ALPN boundary and no-ALPN paths
- Cover TLS handshake completion secret profiles
- Add TLS unsupported cipher state guards
- Assert TLS server state on ALPN and TP paths
- Guard TLS server hello against bad client TP
- Tighten TLS ALPN contract failure coverage
- Expand TLS key schedule derivation coverage
- Add TLS handshake parser negative coverage
- Enforce deterministic TLS adapter failure mapping
- Assert adapter state invariants on failures
- Cover malformed ALPN adapter failure states
- Enforce TLS adapter single-use transitions
- Add TLS adapter negative extension cases
- Verify TLS adapter ALPN and TP exposure
- Add TLS adapter state transition matrix
- Add TLS adapter error mapping coverage
- Expand SSH auth signature negative matrix
- Add SSH zeroization coverage

## [0.0.6] - 2026-03-04

### <!-- 0 -->⛰️  Features

- Add SSH host key and signature management

## [0.0.3] - 2026-03-03

### <!-- 0 -->⛰️  Features

- Remove unused SSH modules
- Implement SSH/QUIC initial handshake structures
- Implement cryptographic context and header protection
- Add server hello validation tests
- Implement basic TLS 1.3 handshake logic
- Init

