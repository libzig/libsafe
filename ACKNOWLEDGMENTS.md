# Acknowledgments

Crypto code should be humble. Tests should be ruthless.

## Codebase references

These upstream projects informed implementation choices and verification strategy:

- **[LSQUIC](https://github.com/litespeedtech/lsquic)**
- **Docs**: https://lsquic.readthedocs.io/
- **[tls.zig](https://github.com/ianic/tls.zig)** for practical TLS 1.2/1.3 handshake structure, transcript management, and broad interoperability/testing patterns.

## Protocol and standards references

These references informed TLS/QUIC and SSH/QUIC primitive behavior:

- **[QUIC Transport (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)**
- **[Using TLS with QUIC (RFC 9001)](https://www.rfc-editor.org/rfc/rfc9001.html)**
- **[QUIC Recovery (RFC 9002)](https://www.rfc-editor.org/rfc/rfc9002.html)**
- **[TLS 1.3 (RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446.html)**
- **[HKDF (RFC 5869)](https://www.rfc-editor.org/rfc/rfc5869.html)**
- **[SSH Protocol (RFC 4251)](https://www.rfc-editor.org/rfc/rfc4251.html)**
- **[SSH Authentication (RFC 4252)](https://www.rfc-editor.org/rfc/rfc4252.html)**
- **[SSH Transport (RFC 4253)](https://www.rfc-editor.org/rfc/rfc4253.html)**
- **[Curve25519 for SSH (RFC 8731)](https://www.rfc-editor.org/rfc/rfc8731.html)**

## Ecosystem references

- **[OpenSSH Portable](https://github.com/openssh/openssh-portable)** for real-world host-key and auth behavior patterns.

Thank you to all maintainers shipping open standards and open implementations. You made this library sturdier.
