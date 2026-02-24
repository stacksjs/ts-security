# ts-security/wip

Work-in-progress security modules for the ts-security monorepo. Contains low-level cryptographic algorithm implementations, protocol handlers, and encoding utilities that are being developed or refactored.

## Status

This package is **not published** and serves as a staging area for modules under active development. Code here may be unstable or incomplete.

## Contents

- **Asymmetric algorithms**: RSA, Ed25519, prime generation, JSBN (big number)
- **Hash algorithms**: MD5, SHA-1, SHA-256, SHA-512
- **Symmetric algorithms**: AES, DES, RC2, cipher modes
- **Encoding**: ASN.1, Base-X, PEM
- **Protocols**: TLS, SSH, socket
- **PKI**: x509, PKCS#1, PSS, MGF1
- **Validators**: ASN.1 validation

## Usage

These modules are intended for internal use within the ts-security monorepo. Import directly from the source files:

```ts
import { rsa } from './algorithms/asymmetric/rsa'
import { sha256 } from './algorithms/hash/sha256'
import { aes } from './algorithms/symmetric/aes'
```

## License

MIT
