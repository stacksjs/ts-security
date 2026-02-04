---
title: Getting Started with ts-security
description: Learn how to implement security features in your application using ts-security
---

# Getting Started

This guide will walk you through setting up security features in your application using ts-security.

## Installation

Install ts-security using your preferred package manager:

```bash
# Using bun
bun add ts-security

# Using npm
npm install ts-security

# Using pnpm
pnpm add ts-security
```

## Quick Start

### Import the Library

```typescript
import {
  aes,
  sha256,
  sha512,
  hmac,
  rsa,
  ed25519,
  pki,
  random,
  tls,
} from 'ts-security'
```

### AES Encryption

Encrypt and decrypt data using AES with various modes:

```typescript
import { aes } from 'ts-security'

// Generate a random key (256-bit for AES-256)
const key = crypto.getRandomValues(new Uint8Array(32))

// Generate a random IV (initialization vector)
const iv = crypto.getRandomValues(new Uint8Array(16))

// Create cipher in GCM mode (recommended for authenticated encryption)
const cipher = aes.createCipher('AES-GCM', key)
cipher.start({ iv })
cipher.update('Hello, World!')
cipher.finish()

const encrypted = cipher.output
const tag = cipher.mode.tag // Authentication tag for GCM

// Decrypt
const decipher = aes.createDecipher('AES-GCM', key)
decipher.start({ iv, tag })
decipher.update(encrypted)
decipher.finish()

const decrypted = decipher.output.toString()
console.log(decrypted) // "Hello, World!"
```

### SHA-256 Hashing

```typescript
import { sha256 } from 'ts-security'

// Create a message digest
const md = sha256.create()
md.update('Hello, World!')
const hash = md.digest()

console.log(hash.toHex())
// "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
```

### HMAC Message Authentication

```typescript
import { hmac } from 'ts-security'

const key = 'secret-key'
const message = 'Hello, World!'

// Create HMAC with SHA-256
const mac = hmac.create()
mac.start('sha256', key)
mac.update(message)
const result = mac.digest()

console.log(result.toHex())
```

### RSA Key Generation and Encryption

```typescript
import { rsa, pki } from 'ts-security'

// Generate RSA key pair
const keypair = rsa.generateKeyPair({
  bits: 2048,
  workers: -1, // Use all available cores
})

// Encrypt with public key
const encrypted = keypair.publicKey.encrypt('Secret message', 'RSA-OAEP', {
  md: sha256.create(),
})

// Decrypt with private key
const decrypted = keypair.privateKey.decrypt(encrypted, 'RSA-OAEP', {
  md: sha256.create(),
})

console.log(decrypted) // "Secret message"
```

### Digital Signatures with Ed25519

```typescript
import { ed25519 } from 'ts-security'

// Generate key pair
const keypair = ed25519.generateKeyPair()

// Sign a message
const message = new TextEncoder().encode('Hello, World!')
const signature = ed25519.sign(message, keypair.privateKey)

// Verify the signature
const isValid = ed25519.verify(signature, message, keypair.publicKey)
console.log(isValid) // true
```

### Secure Random Numbers

```typescript
import { random } from 'ts-security'

// Generate random bytes synchronously
const bytes = random.getBytesSync(32)

// Generate random bytes asynchronously
const asyncBytes = await random.getBytes(32)

// Generate a random hex string
const hex = random.getBytesSync(16).toString('hex')
```

## Certificate Management

### Create a Self-Signed Certificate

```typescript
import { pki, rsa } from 'ts-security'

// Generate key pair
const keys = rsa.generateKeyPair({ bits: 2048 })

// Create certificate
const cert = pki.createCertificate()
cert.publicKey = keys.publicKey
cert.serialNumber = '01'

// Set validity period
cert.validity.notBefore = new Date()
cert.validity.notAfter = new Date()
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

// Set subject and issuer (same for self-signed)
const attrs = [
  { name: 'commonName', value: 'localhost' },
  { name: 'organizationName', value: 'My Organization' },
  { name: 'countryName', value: 'US' },
]
cert.setSubject(attrs)
cert.setIssuer(attrs)

// Add extensions
cert.setExtensions([
  {
    name: 'basicConstraints',
    cA: true,
  },
  {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    keyEncipherment: true,
  },
  {
    name: 'subjectAltName',
    altNames: [
      { type: 2, value: 'localhost' },
      { type: 7, ip: '127.0.0.1' },
    ],
  },
])

// Self-sign the certificate
cert.sign(keys.privateKey, sha256.create())

// Convert to PEM format
const certPem = pki.certificateToPem(cert)
const keyPem = pki.privateKeyToPem(keys.privateKey)

console.log(certPem)
console.log(keyPem)
```

## TLS Connections

### Create a Secure Server

```typescript
import { tls, pki } from 'ts-security'

// Load certificate and key
const cert = pki.certificateFromPem(certPem)
const key = pki.privateKeyFromPem(keyPem)

// Create TLS server options
const serverOptions = {
  key: key,
  cert: cert,
  cipherSuites: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
  ],
}

// Create server (implementation depends on your server framework)
```

### Connect to a TLS Server

```typescript
import { tls } from 'ts-security'

const connection = tls.connect({
  server: 'example.com',
  port: 443,
  verify: (connection, verified, depth, certs) => {
    // Custom certificate verification
    if (depth === 0 && !verified) {
      console.log('Certificate verification failed')
      return false
    }
    return verified
  },
  connected: (connection) => {
    console.log('Connected!')
    connection.prepare('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
  },
  dataReady: (connection) => {
    const data = connection.data.getBytes()
    console.log('Response:', data)
    connection.close()
  },
  error: (connection, error) => {
    console.error('Error:', error.message)
  },
  closed: (connection) => {
    console.log('Connection closed')
  },
})
```

## PEM Encoding/Decoding

```typescript
import { pem } from 'ts-security'

// Decode PEM
const messages = pem.decode(pemString)
for (const msg of messages) {
  console.log('Type:', msg.type) // e.g., "CERTIFICATE", "RSA PRIVATE KEY"
  console.log('Body length:', msg.body.length)
}

// Encode PEM
const encoded = pem.encode({
  type: 'CERTIFICATE',
  body: certificateBytes,
})
```

## Best Practices

### Key Management

```typescript
// Use environment variables for secrets
const secretKey = process.env.ENCRYPTION_KEY

// Generate strong keys
const key = random.getBytesSync(32) // 256-bit key

// Never hardcode keys in source code
// const key = 'hardcoded-secret' // DON'T DO THIS
```

### Secure Defaults

```typescript
// Use authenticated encryption (GCM mode)
const cipher = aes.createCipher('AES-GCM', key)

// Use SHA-256 or higher for hashing
const md = sha256.create()

// Use at least 2048-bit RSA keys
const keypair = rsa.generateKeyPair({ bits: 2048 })
```

### Error Handling

```typescript
try {
  const decipher = aes.createDecipher('AES-GCM', key)
  decipher.start({ iv, tag })
  decipher.update(ciphertext)
  decipher.finish()
} catch (error) {
  // Handle decryption failure (corrupted data, wrong key, tampered data)
  console.error('Decryption failed:', error.message)
}
```

## Next Steps

- Learn about [Certificate Management](/guide/certificates)
- Set up [HTTPS](/guide/https) for your application
- Explore [X.509 Operations](/guide/x509)
- Review the [API Reference](/api/crypto)
