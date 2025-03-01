<p align="center"><img src="../../.github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
<!-- [![npm downloads][npm-downloads-src]][npm-downloads-href] -->
<!-- [![Codecov][codecov-src]][codecov-href] -->

# ts-hash

> A TypeScript implementation of the SHA family of cryptographic hash functions with a focus on type safety, security, and performance.

## Features

- 🔒 **Comprehensive SHA Implementation**
  - SHA-1 _(legacy, not recommended for security-critical applications)_
  - SHA-256 _(part of the SHA-2 family)_
  - SHA-512 with variants _(SHA-384, SHA-512/256, SHA-512/224)_

- 🛡️ **Secure Implementation**
  - Follows NIST standards and specifications
  - Passes standard test vectors
  - Handles edge cases properly

- 🎯 **Type Safety**
  - Full TypeScript support
  - Comprehensive type definitions
  - Strict type checking

- 🧰 **Flexible API**
  - Incremental hashing support
  - Multiple digest formats
  - UTF-8 encoding support
  - ByteStringBuffer input support

## Install

```bash
# bun
bun install ts-hash

# npm
npm install ts-hash

# pnpm
pnpm install ts-hash
```

## Get Started

After installing the package, you can import and use the various hash functions:

```ts
import { sha1, sha256, sha384, sha512, sha512_224, sha512_256 } from 'ts-hash'

// SHA-1 Hashing (legacy, not recommended for security-critical applications)
const md1 = sha1.create()
md1.update('Hello, World!')
const hash1 = md1.digest().toHex()

// SHA-256 Hashing
const md2 = sha256.create()
md2.update('Hello, World!')
const hash2 = md2.digest().toHex()

// SHA-512 Hashing
const md3 = sha512.create()
md3.update('Hello, World!')
const hash3 = md3.digest().toHex()

// SHA-384 Hashing
const md4 = sha384
md4.update('Hello, World!')
const hash4 = md4.digest().toHex()

// SHA-512/256 Hashing
const md5 = sha512_256
md5.update('Hello, World!')
const hash5 = md5.digest().toHex()

// SHA-512/224 Hashing
const md6 = sha512_224
md6.update('Hello, World!')
const hash6 = md6.digest().toHex()

// Incremental hashing
const md = sha256.create()
md.update('Part 1 of the message')
md.update('Part 2 of the message')
md.update('Part 3 of the message')
const hash = md.digest().toHex()
```

## API Reference

### Common Interface

All hash functions implement the `MessageDigest` interface:

```ts
interface MessageDigest {
  algorithm: string // The name of the algorithm (e.g., 'sha256')
  blockLength: number // The block size in bytes
  digestLength: number // The digest size in bytes
  messageLength: number // The current message length

  // Resets the hash state
  start: () => MessageDigest

  // Updates the hash with new data
  update: (msg: string | ByteStringBuffer, encoding?: string) => MessageDigest

  // Finalizes the hash computation and returns the digest
  digest: () => ByteStringBuffer
}
```

### SHA-1

```ts
const md = sha1.create()
```

- Block size: 64 bytes
- Digest size: 20 bytes (160 bits)

### SHA-256

```ts
const md = sha256.create()
```

- Block size: 64 bytes
- Digest size: 32 bytes (256 bits)

### SHA-512

```ts
const md = sha512.create()
```

- Block size: 128 bytes
- Digest size: 64 bytes (512 bits)

### SHA-384

```ts
const md = sha384
```

- Block size: 128 bytes
- Digest size: 48 bytes (384 bits)

### SHA-512/256

```ts
const md = sha512_256
```

- Block size: 128 bytes
- Digest size: 32 bytes (256 bits)

### SHA-512/224

```ts
const md = sha512_224
```

- Block size: 128 bytes
- Digest size: 28 bytes (224 bits)

## Testing

```bash
bun test
```

## Changelog

Please see our [releases](https://github.com/stacksjs/ts-hash/releases) page for more information on what has changed recently.

## Contributing

Please review the [Contributing Guide](https://github.com/stacksjs/contributing) for details.

## Community

For help, discussion about best practices, or any other conversation that would benefit from being searchable:

[Discussions on GitHub](https://github.com/stacksjs/stacks/discussions)

For casual chit-chat with others using this package:

[Join the Stacks Discord Server](https://discord.gg/stacksjs)

## Postcardware

"Software that is free, but hopes for a postcard." We love receiving postcards from around the world showing where `ts-hash` is being used! We showcase them on our website too.

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
[npm-version-src]: https://img.shields.io/npm/v/@stacksjs/ts-hash?style=flat-square
[npm-version-href]: https://npmjs.com/package/@stacksjs/ts-hash
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-hash/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-hash/actions?query=workflow%3Aci

<!-- [codecov-src]: https://img.shields.io/codecov/c/gh/stacksjs/ts-hash/main?style=flat-square
[codecov-href]: https://codecov.io/gh/stacksjs/ts-hash -->
