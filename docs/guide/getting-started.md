---
title: Getting Started with ts-security
description: Learn how to implement security features in your application using ts-security
---
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
