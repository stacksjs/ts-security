# ts-base-x

A base-x encoding and decoding library. Supports Base2, Base8, Base11, Base16, Base32, Base36, Base58, Base62, Base64, Base67, and custom alphabets.

## Installation

```bash
bun add ts-base-x
# or
npm install ts-base-x
```

## Usage

```ts
import { base58, base64, base, ALPHABETS } from 'ts-base-x'

// Use pre-configured converters
const encoded = base58.encode(new Uint8Array([1, 2, 3]))
const decoded = base58.decode(encoded)

const b64 = base64.encode(new Uint8Array([72, 101, 108, 108, 111]))

// Create a custom base converter
const custom = base(ALPHABETS.BASE32)
const result = custom.encode(new Uint8Array([255, 128]))
```

## Features

- Pre-configured converters for Base2, Base8, Base11, Base16, Base32, Base32z, Base36, Base58, Base62, Base64, and Base67
- Create custom base converters with any alphabet
- Encode `Uint8Array` or `ArrayBuffer` to string
- Decode base-x strings back to `Uint8Array`
- Zero-dependency, lightweight implementation

## License

MIT
