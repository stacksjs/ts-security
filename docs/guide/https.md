---
title: HTTPS Setup
description: Complete guide to setting up HTTPS with ts-security
---

# HTTPS Setup

This guide covers setting up HTTPS for your applications using ts-security, including local development and production configurations.

## Overview

HTTPS (HTTP Secure) encrypts communication between clients and servers using TLS/SSL. ts-security provides:

- Certificate generation for development
- TLS connection handling
- Certificate validation
- Cipher suite configuration

## Local Development Setup

### Quick Start for localhost

```typescript
import { pki, rsa, tls } from 'ts-security'

// Generate self-signed certificate for localhost
function createLocalhostCertificate() {
  const keys = rsa.generateKeyPair({ bits: 2048 })
  const cert = pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = Date.now().toString(16)

  // 1 year validity
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 1
  )

  const attrs = [
    { shortName: 'CN', value: 'localhost' },
    { shortName: 'O', value: 'Development' },
  ]

  cert.setSubject(attrs)
  cert.setIssuer(attrs)

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
    },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'localhost' },
        { type: 2, value: '*.localhost' },
        { type: 7, ip: '127.0.0.1' },
        { type: 7, ip: '::1' },
      ],
    },
  ])

  cert.sign(keys.privateKey)

  return {
    cert: pki.certificateToPem(cert),
    key: pki.privateKeyToPem(keys.privateKey),
  }
}
```

### Using with Bun Server

```typescript
import { createLocalhostCertificate } from './certificates'

const { cert, key } = createLocalhostCertificate()

Bun.serve({
  port: 3000,
  tls: {
    cert,
    key,
  },
  fetch(req) {
    return new Response('Hello, HTTPS!')
  },
})

console.log('Server running at https://localhost:3000')
```

### Using with Node.js

```typescript
import https from 'node:https'
import { createLocalhostCertificate } from './certificates'

const { cert, key } = createLocalhostCertificate()

const server = https.createServer({ cert, key }, (req, res) => {
  res.writeHead(200)
  res.end('Hello, HTTPS!')
})

server.listen(3000, () => {
  console.log('Server running at https://localhost:3000')
})
```

## Custom Development Domains

### Setup Local CA

For custom domains like `*.dev.local`:

```typescript
import { pki, rsa } from 'ts-security'
import fs from 'node:fs'

class LocalCA {
  private caKey: any
  private caCert: any

  constructor() {
    this.initCA()
  }

  private initCA() {
    const caKeyPath = './.certs/ca-key.pem'
    const caCertPath = './.certs/ca-cert.pem'

    // Check if CA already exists
    if (fs.existsSync(caKeyPath) && fs.existsSync(caCertPath)) {
      this.caKey = pki.privateKeyFromPem(
        fs.readFileSync(caKeyPath, 'utf-8')
      )
      this.caCert = pki.certificateFromPem(
        fs.readFileSync(caCertPath, 'utf-8')
      )
      return
    }

    // Create new CA
    const keys = rsa.generateKeyPair({ bits: 4096 })
    const cert = pki.createCertificate()

    cert.publicKey = keys.publicKey
    cert.serialNumber = '01'

    cert.validity.notBefore = new Date()
    cert.validity.notAfter = new Date()
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 10
    )

    const attrs = [
      { shortName: 'CN', value: 'Local Development CA' },
      { shortName: 'O', value: 'Development' },
    ]

    cert.setSubject(attrs)
    cert.setIssuer(attrs)

    cert.setExtensions([
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    ])

    cert.sign(keys.privateKey)

    // Save CA
    fs.mkdirSync('./.certs', { recursive: true })
    fs.writeFileSync(caKeyPath, pki.privateKeyToPem(keys.privateKey))
    fs.writeFileSync(caCertPath, pki.certificateToPem(cert))

    this.caKey = keys.privateKey
    this.caCert = cert
  }

  createCertificate(domains: string[]) {
    const keys = rsa.generateKeyPair({ bits: 2048 })
    const cert = pki.createCertificate()

    cert.publicKey = keys.publicKey
    cert.serialNumber = Date.now().toString(16)

    cert.validity.notBefore = new Date()
    cert.validity.notAfter = new Date()
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    )

    cert.setSubject([{ shortName: 'CN', value: domains[0] }])
    cert.setIssuer(this.caCert.subject.attributes)

    const altNames = domains.map(domain => ({
      type: 2,
      value: domain,
    }))

    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyEncipherment: true,
      },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames },
    ])

    cert.sign(this.caKey)

    return {
      cert: pki.certificateToPem(cert),
      key: pki.privateKeyToPem(keys.privateKey),
      ca: pki.certificateToPem(this.caCert),
    }
  }

  getCACertificate() {
    return pki.certificateToPem(this.caCert)
  }
}

// Usage
const ca = new LocalCA()
const { cert, key } = ca.createCertificate([
  'myapp.dev.local',
  '*.myapp.dev.local',
])
```

### Trust the CA Certificate

After creating the CA, you need to trust it on your system:

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./.certs/ca-cert.pem
```

**Linux (Ubuntu/Debian):**
```bash
sudo cp ./.certs/ca-cert.pem /usr/local/share/ca-certificates/local-dev-ca.crt
sudo update-ca-certificates
```

**Windows:**
```powershell
Import-Certificate -FilePath .\.certs\ca-cert.pem -CertStoreLocation Cert:\LocalMachine\Root
```

## TLS Configuration

### Modern Cipher Suites

```typescript
import { tls } from 'ts-security'

// Recommended cipher suites for modern security
const modernCipherSuites = [
  // TLS 1.3 (preferred)
  'TLS_AES_256_GCM_SHA384',
  'TLS_AES_128_GCM_SHA256',
  'TLS_CHACHA20_POLY1305_SHA256',

  // TLS 1.2 fallback (still secure)
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
]

const tlsOptions = {
  cipherSuites: modernCipherSuites,
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',
}
```

### Server Configuration

```typescript
import { tls, pki } from 'ts-security'

function createSecureServer(cert: string, key: string) {
  return {
    tls: {
      cert,
      key,

      // Cipher suite configuration
      ciphers: [
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
      ].join(':'),

      // Enable OCSP stapling if supported
      // requestOCSP: true,

      // Session tickets for performance
      sessionTimeout: 300, // 5 minutes
    },
  }
}
```

## Client Connections

### Making HTTPS Requests

```typescript
import { tls, pki } from 'ts-security'

async function secureRequest(url: string, options?: {
  ca?: string
  cert?: string
  key?: string
  rejectUnauthorized?: boolean
}) {
  const urlObj = new URL(url)

  return new Promise((resolve, reject) => {
    const connection = tls.connect({
      server: urlObj.hostname,
      port: Number.parseInt(urlObj.port) || 443,

      // Custom CA for self-signed certs
      caStore: options?.ca ? [pki.certificateFromPem(options.ca)] : undefined,

      // Client certificate (mutual TLS)
      certificate: options?.cert ? pki.certificateFromPem(options.cert) : undefined,
      privateKey: options?.key ? pki.privateKeyFromPem(options.key) : undefined,

      verify: (conn, verified, depth, certs) => {
        if (options?.rejectUnauthorized === false) {
          return true
        }
        return verified
      },

      connected: (conn) => {
        const request = `GET ${urlObj.pathname} HTTP/1.1\r\n`
          + `Host: ${urlObj.hostname}\r\n`
          + `Connection: close\r\n`
          + `\r\n`

        conn.prepare(request)
      },

      dataReady: (conn) => {
        const response = conn.data.getBytes()
        resolve(response)
      },

      error: (conn, error) => {
        reject(new Error(error.message))
      },

      closed: () => {
        // Connection closed
      },
    })
  })
}
```

### Certificate Pinning

```typescript
import { pki, sha256 } from 'ts-security'

function getPinFromCertificate(certPem: string): string {
  const cert = pki.certificateFromPem(certPem)
  const publicKeyDer = pki.publicKeyToPem(cert.publicKey)

  const md = sha256.create()
  md.update(publicKeyDer)
  return md.digest().toHex()
}

function verifyPin(certPem: string, expectedPin: string): boolean {
  const actualPin = getPinFromCertificate(certPem)
  return actualPin === expectedPin
}

// Usage
const expectedPin = 'abc123...' // Your pinned certificate hash

tls.connect({
  server: 'api.example.com',
  port: 443,

  verify: (conn, verified, depth, certs) => {
    if (depth === 0) {
      // Verify leaf certificate pin
      const certPem = pki.certificateToPem(certs[0])
      if (!verifyPin(certPem, expectedPin)) {
        console.error('Certificate pin mismatch!')
        return false
      }
    }
    return verified
  },

  // ... other options
})
```

## Mutual TLS (mTLS)

### Server with Client Authentication

```typescript
import { pki } from 'ts-security'

const serverOptions = {
  cert: serverCertPem,
  key: serverKeyPem,

  // Request client certificate
  requestCert: true,
  rejectUnauthorized: true,

  // CA(s) to validate client certificates
  ca: [clientCAPem],
}

// With Bun
Bun.serve({
  port: 443,
  tls: serverOptions,
  fetch(req, server) {
    // Access client certificate
    const clientCert = server.requestIP(req) // Check for client cert

    return new Response('Authenticated!')
  },
})
```

### Client with Certificate

```typescript
import { tls, pki } from 'ts-security'

const clientCert = pki.certificateFromPem(clientCertPem)
const clientKey = pki.privateKeyFromPem(clientKeyPem)
const serverCA = pki.certificateFromPem(serverCAPem)

tls.connect({
  server: 'api.example.com',
  port: 443,

  // Client certificate
  certificate: clientCert,
  privateKey: clientKey,

  // Server CA for validation
  caStore: [serverCA],

  verify: (conn, verified, depth, certs) => verified,

  connected: (conn) => {
    console.log('mTLS connection established')
    // Proceed with secure communication
  },
})
```

## HTTPS Proxy

### Create HTTPS Proxy

```typescript
import { tls, pki } from 'ts-security'

function createProxy(targetHost: string, targetPort: number) {
  return {
    handleConnect(clientSocket: any, targetHostname: string) {
      // Create TLS connection to target
      const target = tls.connect({
        server: targetHostname,
        port: targetPort,

        connected: (conn) => {
          // Pipe data between client and target
          clientSocket.on('data', (data: Buffer) => {
            conn.prepare(data.toString())
          })
        },

        dataReady: (conn) => {
          const data = conn.data.getBytes()
          clientSocket.write(data)
        },

        closed: () => {
          clientSocket.end()
        },
      })
    },
  }
}
```

## Debugging TLS Issues

### Certificate Chain Verification

```typescript
import { pki } from 'ts-security'

function debugCertificateChain(certPem: string, caCertPem?: string) {
  const cert = pki.certificateFromPem(certPem)

  console.log('Certificate Information:')
  console.log('  Subject:', cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', '))
  console.log('  Issuer:', cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(', '))
  console.log('  Valid From:', cert.validity.notBefore)
  console.log('  Valid To:', cert.validity.notAfter)
  console.log('  Serial:', cert.serialNumber)

  // Check expiry
  const now = new Date()
  if (now < cert.validity.notBefore) {
    console.log('  WARNING: Certificate not yet valid')
  }
  if (now > cert.validity.notAfter) {
    console.log('  WARNING: Certificate expired')
  }

  // Check chain if CA provided
  if (caCertPem) {
    const caCert = pki.certificateFromPem(caCertPem)
    const caStore = pki.createCaStore([caCert])

    try {
      pki.verifyCertificateChain(caStore, [cert])
      console.log('  Chain: VALID')
    } catch (error) {
      console.log('  Chain: INVALID -', error.message)
    }
  }
}
```

## Next Steps

- Learn about [X.509 Operations](/guide/x509)
- Review [Certificate Management](/guide/certificates)
- Explore the [TLS API Reference](/api/tls)
