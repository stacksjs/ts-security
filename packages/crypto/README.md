# ts-security-crypto

Cryptographic utilities using Bun native features. Provides hashing, encryption, password hashing, and key generation.

## Installation

```bash
bun add ts-security-crypto
# or
npm install ts-security-crypto
```

## Usage

```ts
import {
  sha256,
  hmac,
  encrypt,
  decrypt,
  hashPassword,
  verifyPassword,
  generateKey,
  generateUUID,
} from 'ts-security-crypto'

// Hashing
const hash = sha256('Hello, World!')
const mac = hmac('message', 'secret-key', 'sha256', 'hex')

// AES-GCM encryption/decryption
const { encrypted, iv } = await encrypt('secret message', 'passphrase')
const plaintext = await decrypt(encrypted, 'passphrase')

// Password hashing (bcrypt, argon2id, argon2i, argon2d)
const hashed = await hashPassword('my-password', { algorithm: 'argon2id' })
const isValid = await verifyPassword('my-password', hashed)

// Key generation
const appKey = generateKey(32) // "base64:..."
const uuid = generateUUID()
```

## Features

- Hashing: MD5, SHA-1, SHA-256, SHA-512, BLAKE2b-256
- HMAC generation with SHA-256 and SHA-512
- AES-GCM and AES-CBC encryption/decryption with PBKDF2 key derivation
- Password hashing with bcrypt, argon2id, argon2i, and argon2d
- Secure key generation, hex strings, UUIDs, and random bytes
- Built on Bun native crypto and Web Crypto API

## License

MIT
