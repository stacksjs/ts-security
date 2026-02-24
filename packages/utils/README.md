# ts-security-utils

A collection of utility functions for the ts-security package. Provides base64 encoding/decoding, hex conversion, buffer operations, and a cryptographically-secure PRNG.

## Installation

```bash
bun add ts-security-utils
# or
npm install ts-security-utils
```

## Usage

```ts
import {
  encode64,
  decode64,
  bytesToHex,
  hexToBytes,
  encodeUtf8,
  decodeUtf8,
  createBuffer,
  random,
} from 'ts-security-utils'

// Base64 encoding/decoding
const encoded = encode64('Hello, World!')
const decoded = decode64(encoded)

// Hex conversion
const hex = bytesToHex(someBytes)
const bytes = hexToBytes('48656c6c6f')

// UTF-8 encoding
const utf8 = encodeUtf8('Hello')

// Buffer operations
const buf = createBuffer()
buf.putBytes('data')
buf.putInt32(42)

// Cryptographically-secure random bytes
const randomBytes = random.getBytesSync(16)
```

## Features

- Base64 encoding and decoding with optional line wrapping
- Hex-to-bytes and bytes-to-hex conversion
- UTF-8 encoding and decoding
- `ByteStringBuffer` for binary data manipulation
- Fortuna-based CSPRNG (AES-128 counter mode)
- Hardware concurrency estimation

## License

MIT
