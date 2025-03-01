<p align="center"><img src="../../.github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
<!-- [![npm downloads][npm-downloads-src]][npm-downloads-href] -->
<!-- [![Codecov][codecov-src]][codecov-href] -->

# ts-asn1

> A TypeScript implementation of ASN.1 encoding and decoding with a focus on type safety and standards compliance.

## Features

- 🔒 **DER Compliant** _Implements ASN.1 encoding & decoding according to standard_
- 🔄 **Comprehensive Type Support** _Support for INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE, SET, and more_
- 🧩 **Validation** _Validate ASN.1 structures against expected schemas_
- 🔧 **Flexible Parsing** _Support for both strict DER and more lenient BER parsing_
- 🛡️ **Type Safety** _Full TypeScript support with comprehensive type definitions_
- 🪶 **Lightweight** _No dependencies_
- 🔍 **Debugging** _Pretty printing of ASN.1 structures for easier debugging_

## Install

```bash
# bun
bun install ts-asn1

# npm
npm install ts-asn1

# pnpm
pnpm install ts-asn1
```

## Get Started

After installing the package, you can import and use the ASN.1 encoding and decoding functions:

```ts
import { asn1 } from 'ts-asn1'
import { utils } from 'ts-security-utils'

// Create an ASN.1 INTEGER
const intValue = asn1.integerToDer(123)
console.log(utils.bytesToHex(intValue)) // "7b"

// Parse ASN.1 DER encoded data
const derData = utils.hexToBytes('300a02010102010202010304010a')
const asn1Object = asn1.fromDer(derData)
console.log(asn1.prettyPrint(asn1Object))
// SEQUENCE {
//   INTEGER 1
//   INTEGER 2
//   INTEGER 3
//   OCTET STRING 0a
// }

// Convert dates to/from ASN.1 generalized time
const date = new Date('2025-03-01T12:00:00Z')
const genTime = asn1.dateToGeneralizedTime(date)
console.log(genTime) // "20250301120000Z"

// Convert back to a date
const parsedDate = asn1.generalizedTimeToDate(genTime)
console.log(parsedDate.toISOString()) // "2025-03-01T12:00:00.000Z"
```

## API Reference

### ASN.1 Types

The library supports all standard ASN.1 types:

```ts
const Type = {
  BOOLEAN: 1,
  INTEGER: 2,
  BITSTRING: 3,
  OCTETSTRING: 4,
  NULL: 5,
  OID: 6,
  OBJECT_DESCRIPTOR: 7,
  EXTERNAL: 8,
  REAL: 9,
  ENUMERATED: 10,
  EMBEDDED_PDV: 11,
  UTF8: 12,
  RELATIVE_OID: 13,
  SEQUENCE: 16,
  SET: 17,
  NUMERIC_STRING: 18,
  PRINTABLE_STRING: 19,
  T61_STRING: 20,
  VIDEOTEX_STRING: 21,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  GRAPHIC_STRING: 25,
  VISIBLE_STRING: 26,
  GENERAL_STRING: 27,
  UNIVERSAL_STRING: 28,
  CHARACTER_STRING: 29,
  BMP_STRING: 30
} as const
```

### ASN.1 Tag Classes

```ts
const Class = {
  UNIVERSAL: 0,
  APPLICATION: 1,
  CONTEXT_SPECIFIC: 2,
  PRIVATE: 3
} as const
```

### Key Functions

#### Encoding/Decoding

```ts
// Convert to/from DER encoding
function fromDer(bytes: Uint8Array, options?: FromDerOptions): Asn1Object
function toDer(obj: Asn1Object): Buffer

// Convert integers to/from DER
function integerToDer(n: number): Buffer
function derToInteger(bytes: Uint8Array): number

// Convert OIDs to/from DER
function oidToDer(oid: string): Buffer
function derToOid(bytes: Uint8Array): string

// Date conversions
function dateToGeneralizedTime(date: Date): string
function generalizedTimeToDate(genTime: string): Date
function dateToUtcTime(date: Date): string
function utcTimeToDate(utcTime: string): Date
```

#### Utility Functions

```ts
// Create a copy of an ASN.1 object
function copy(obj: Asn1Object): Asn1Object

// Compare two ASN.1 objects for equality
function equals(obj1: any, obj2: any): boolean

// Validate an ASN.1 object against a schema
function validate(obj: Asn1Object, validator: Validator, capture?: Record<string, any>, errors?: string[]): boolean

// Pretty print an ASN.1 object for debugging
function prettyPrint(obj: Asn1Object, indent?: string): string
```

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

"Software that is free, but hopes for a postcard." We love receiving postcards from around the world showing where `ts-asn1` is being used! We showcase them on our website too.

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
[npm-version-src]: https://img.shields.io/npm/v/@stacksjs/ts-asn1?style=flat-square
[npm-version-href]: https://npmjs.com/package/@stacksjs/ts-asn1
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-security/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-security/actions?query=workflow%3Aci

<!-- [codecov-src]: https://img.shields.io/codecov/c/gh/stacksjs/ts-asn1/main?style=flat-square
[codecov-href]: https://codecov.io/gh/stacksjs/ts-asn1 -->
