# ts-security

A library of security utilities. Written in TypeScript. Optimized for Node/Bun/Browser environments.

## Installation

```bash
bun add ts-security
# or
npm install ts-security
```

## Usage

```ts
import { rsa, ed25519, aes, sha256, pem, asn1, tls } from 'ts-security'

// RSA key pair generation
const keyPair = rsa.generateKeyPair(2048)

// SHA-256 hashing
const digest = sha256.create()
digest.update('Hello, World!')
const hash = digest.digest()

// PEM encoding/decoding
const pemBlock = pem.encode(data, 'RSA PRIVATE KEY')
```

## Features

- Asymmetric algorithms: RSA, Ed25519
- Hash algorithms: MD5, SHA-1, SHA-256, SHA-512
- Symmetric algorithms: AES, DES, RC2 with multiple cipher modes
- Encoding: ASN.1, PEM, Base-X
- Protocols: TLS, SSH, socket support
- PKI and PKCS#1 utilities
- ASN.1 validation
- Cross-environment support (Node.js, Bun, Browser)

## License

MIT
