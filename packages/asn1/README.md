<p align="center"><img src="../../.github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
<!-- [![npm downloads][npm-downloads-src]][npm-downloads-href] -->
<!-- [![Codecov][codecov-src]][codecov-href] -->

# ts-pem

> A TypeScript implementation of PEM (Privacy Enhanced Mail) encoding and decoding with a focus on type safety and standards compliance.

## Features

- 🔒 **RFC 1421 Compliant** _Implements PEM encoding & decoding according to standard_
- 📦 **Versatile Handling** _Support for multiple PEM messages in a single string_
- 🔄 **Header Processing** _Proper handling of PEM headers including Proc-Type, Content-Domain, and DEK-Info_
- 🧩 **CSR Support** _Special handling for Certificate Signing Requests with NEW prefix_
- 🔧 **Customizable Output** _Control over line length in encoded PEM output_
- 🛡️ **Type Safety** _Full TypeScript support with comprehensive type definitions_
- 🪶 **Lightweight** _No dependencies other than_

## Install

```bash
# bun
bun install ts-pem

# npm
npm install ts-pem

# pnpm
pnpm install ts-pem
```

## Get Started

After installing the package, you can import and use the PEM encoding and decoding functions:

```ts
import { encode, decode } from 'ts-pem'

// Decode a PEM-formatted string
const pemString = `-----BEGIN CERTIFICATE-----
MIIBPAIBAAJBALjXU+IdHkSkdBscgXf+EBoa55ruAIsU50uDFjFBkp+rWFt5AOGF
9xL1/HNIby5M64BCw021nJTZKEOmXKdmzYsCAwEAAQ==
-----END CERTIFICATE-----`

const messages = decode(pemString)
console.log(messages[0].type) // 'CERTIFICATE'

// Create and encode a PEM message
const newMessage = {
  type: 'RSA PRIVATE KEY',
  procType: null,
  contentDomain: null,
  dekInfo: null,
  headers: [],
  body: new TextEncoder().encode('your-binary-data-here')
}

const encodedPem = encode(newMessage)
console.log(encodedPem)
// -----BEGIN RSA PRIVATE KEY-----
// eW91ci1iaW5hcnktZGF0YS1oZXJl
// -----END RSA PRIVATE KEY-----
```

## API Reference

### Decode

```ts
function decode(str: string): PEMMessage[]
```

Decodes a PEM-formatted string into an array of PEM message objects.

- **Parameters**:
  - `str`: The PEM-formatted string to decode
- **Returns**: An array of `PEMMessage` objects

### Encode

```ts
function encode(msg: PEMMessage, options?: PEMEncodeOptions): string
```

Encodes a PEM message object into a PEM-formatted string.

- **Parameters**:
  - `msg`: The PEM message object to encode
  - `options`: Optional encoding options
    - `maxline`: Maximum characters per line for the body (default: 64)
- **Returns**: A PEM-formatted string

### PEMMessage Interface

```ts
interface PEMMessage {
  type: string;              // The type of message (e.g., "RSA PRIVATE KEY")
  procType: ProcType | null; // Processing type information
  contentDomain: string | null; // Content domain (typically "RFC822")
  dekInfo: DEKInfo | null;   // Data Encryption Key information
  headers: PEMHeader[];      // Additional headers
  body: Uint8Array;          // The binary-encoded body
}
```

## Testing

```bash
bun test
```

## Changelog

Please see our [releases](https://github.com/stacksjs/ts-pem/releases) page for more information on what has changed recently.

## Contributing

Please review the [Contributing Guide](https://github.com/stacksjs/contributing) for details.

## Community

For help, discussion about best practices, or any other conversation that would benefit from being searchable:

[Discussions on GitHub](https://github.com/stacksjs/stacks/discussions)

For casual chit-chat with others using this package:

[Join the Stacks Discord Server](https://discord.gg/stacksjs)

## Postcardware

"Software that is free, but hopes for a postcard." We love receiving postcards from around the world showing where `ts-pem` is being used! We showcase them on our website too.

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
[npm-version-src]: https://img.shields.io/npm/v/@stacksjs/ts-pem?style=flat-square
[npm-version-href]: https://npmjs.com/package/@stacksjs/ts-pem
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-pem/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-pem/actions?query=workflow%3Aci

<!-- [codecov-src]: https://img.shields.io/codecov/c/gh/stacksjs/ts-pem/main?style=flat-square
[codecov-href]: https://codecov.io/gh/stacksjs/ts-pem -->
