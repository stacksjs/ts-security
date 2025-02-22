<p align="center"><img src=".github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
<!-- [![npm downloads][npm-downloads-src]][npm-downloads-href] -->
<!-- [![Codecov][codecov-src]][codecov-href] -->

# ts-security

> A comprehensive TypeScript security library providing cryptographic primitives and utilities with a focus on type safety, security, performance, and modern best practices.

## Features

- 🔒 **Cryptographic Primitives**
  - AES encryption _(128/192/256-bit)_ with multiple modes _(ECB, CBC, CFB, OFB, CTR, GCM)_
  - SHA-2 family hash functions _(SHA-256, SHA-384, SHA-512)_
  - HMAC message authentication
  - RSA encryption and signing
  - Ed25519 digital signatures

- 🛡️ **Secure Random Number Generation**
  - Fortuna CSPRNG implementation
  - Multiple entropy sources
  - Automatic reseeding
  - Browser and Bun / Node.js support

- 📜 **Certificate Management**
  - X.509 certificate handling
  - PEM encoding/decoding
  - Certificate signing request _(CSR)_ creation
  - Certificate chain validation

- 🔐 **TLS/SSL Support**
  - TLS protocol implementation
  - Secure socket connections
  - Certificate-based authentication
  - Modern cipher suite support

- 🎯 **Type Safety**
  - Full TypeScript support
  - Comprehensive type definitions
  - Strict type checking
  - Modern ES6+ features

- 🧰 **Utilities**
  - Base-N encoding _(Base64, Base58, etc.)_
  - ASN.1 encoding/decoding
  - BigInteger arithmetic
  - Buffer manipulation

## Install

```bash
# bun
bun install ts-security

# npm
npm install ts-security

# pnpm
pnpm install ts-security
```

## Get Started

After installing the package, you can import and use the various cryptographic functions:

```ts
import {
  aes,
  ed25519,
  hmac,
  pki,
  random,
  rsa,
  sha256,
  sha512,
  tls
} from 'ts-security'

// AES Encryption
const cipher = aes.createCipher('AES-GCM', key)
cipher.start({ iv })
cipher.update(data)
const encrypted = cipher.finish()

// SHA-256 Hashing
const md = sha256.create()
md.update('Hello, World!')
const hash = md.digest().toHex()

// Secure Random Numbers
const bytes = random.getBytesSync(32)

// RSA Key Generation
const keypair = rsa.generateKeyPair({ bits: 2048 })

// Digital Signatures
const signature = ed25519.sign(message, privateKey)
const isValid = ed25519.verify(signature, message, publicKey)

// Certificate Operations
const cert = pki.createCertificate()
cert.publicKey = keypair.publicKey
cert.sign(keypair.privateKey)

// TLS Connections
const connection = tls.connect({
  server: host,
  port: 443,
  caStore: [/* trusted certificates */]
})
```

For more detailed examples and API documentation, please visit our [documentation](https://ts-security.stacksjs.org).

## Testing

```bash
bun test
```

## Changelog

Please see our [releases](https://github.com/stacksjs/ts-security/releases) page for more information on what has changed recently.

## Contributing

Please review the [Contributing Guide](https://github.com/stacksjs/contributing) for details.

## Community

For help, discussion about best practices, or any other conversation that would benefit from being searchable:

[Discussions on GitHub](https://github.com/stacksjs/stacks/discussions)

For casual chit-chat with others using this package:

[Join the Stacks Discord Server](https://discord.gg/stacksjs)

## Postcardware

“Software that is free, but hopes for a postcard.” We love receiving postcards from around the world showing where `ts-security` is being used! We showcase them on our website too.

Our address: Stacks.js, 12665 Village Ln #2306, Playa Vista, CA 90094, United States 🌎

## Sponsors

We would like to extend our thanks to the following sponsors for funding Stacks development. If you are interested in becoming a sponsor, please reach out to us.

- [JetBrains](https://www.jetbrains.com/)
- [The Solana Foundation](https://solana.com/)

## Credits

- [Dave Longley](https://github.com/dlongley)
- [node-forge](https://github.com/digitalbazaar/forge)
- [Chris Breuer](https://github.com/chrisbbreuer)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [LICENSE](https://github.com/stacksjs/stacks/tree/main/LICENSE.md) for more information.

Made with 💙

<!-- Badges -->
[npm-version-src]: https://img.shields.io/npm/v/@stacksjs/ts-security?style=flat-square
[npm-version-href]: https://npmjs.com/package/@stacksjs/ts-security
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-security/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-security/actions?query=workflow%3Aci

<!-- [codecov-src]: https://img.shields.io/codecov/c/gh/stacksjs/ts-security/main?style=flat-square
[codecov-href]: https://codecov.io/gh/stacksjs/ts-security -->
