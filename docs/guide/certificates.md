---
title: Certificate Management
description: Comprehensive guide to managing SSL/TLS certificates with ts-security
---

# Certificate Management

This guide covers creating, managing, and working with SSL/TLS certificates using ts-security.

## Overview

Certificates are essential for:

- HTTPS/TLS connections
- Code signing
- Email encryption (S/MIME)
- Client authentication
- API security

## Creating Self-Signed Certificates

### Basic Self-Signed Certificate

```typescript
import { pki, rsa } from 'ts-security'

async function createSelfSignedCert() {
  // Generate RSA key pair
  const keys = rsa.generateKeyPair({ bits: 2048 })

  // Create certificate
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey

  // Set serial number (should be unique)
  cert.serialNumber = Date.now().toString(16)

  // Set validity period
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 1
  )

  // Set subject attributes
  const attrs = [
    { shortName: 'CN', value: 'localhost' },
    { shortName: 'O', value: 'My Organization' },
    { shortName: 'OU', value: 'Development' },
    { shortName: 'C', value: 'US' },
    { shortName: 'ST', value: 'California' },
    { shortName: 'L', value: 'San Francisco' },
  ]

  cert.setSubject(attrs)
  cert.setIssuer(attrs) // Same as subject for self-signed

  // Add extensions
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
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

  // Self-sign the certificate
  cert.sign(keys.privateKey, sha256.create())

  return {
    certificate: pki.certificateToPem(cert),
    privateKey: pki.privateKeyToPem(keys.privateKey),
    publicKey: pki.publicKeyToPem(keys.publicKey),
  }
}
```

### Certificate with Multiple Domains (SAN)

```typescript
import { pki, rsa } from 'ts-security'

function createMultiDomainCert(domains: string[]) {
  const keys = rsa.generateKeyPair({ bits: 2048 })
  const cert = pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = Date.now().toString(16)

  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 1
  )

  // Use first domain as CN
  cert.setSubject([{ shortName: 'CN', value: domains[0] }])
  cert.setIssuer([{ shortName: 'CN', value: domains[0] }])

  // Add all domains to SAN
  const altNames = domains.map(domain => ({
    type: 2, // DNS
    value: domain,
  }))

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
      altNames,
    },
  ])

  cert.sign(keys.privateKey, sha256.create())

  return {
    certificate: pki.certificateToPem(cert),
    privateKey: pki.privateKeyToPem(keys.privateKey),
  }
}

// Usage
const { certificate, privateKey } = createMultiDomainCert([
  'example.com',
  'www.example.com',
  'api.example.com',
])
```

## Certificate Authority (CA)

### Create a Root CA

```typescript
import { pki, rsa } from 'ts-security'

function createRootCA(options: {
  commonName: string
  organization: string
  validityYears?: number
}) {
  const keys = rsa.generateKeyPair({ bits: 4096 }) // Use 4096 for CA

  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'

  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + (options.validityYears || 10)
  )

  const attrs = [
    { shortName: 'CN', value: options.commonName },
    { shortName: 'O', value: options.organization },
  ]

  cert.setSubject(attrs)
  cert.setIssuer(attrs)

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
      pathLenConstraint: 0, // Can only sign end-entity certs
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
  ])

  cert.sign(keys.privateKey, sha256.create())

  return {
    caCert: pki.certificateToPem(cert),
    caKey: pki.privateKeyToPem(keys.privateKey),
    certificate: cert,
    privateKey: keys.privateKey,
  }
}
```

### Sign Certificates with CA

```typescript
import { pki, rsa } from 'ts-security'

function signCertificateWithCA(
  caCert: any,
  caKey: any,
  options: {
    commonName: string
    domains?: string[]
    validityDays?: number
  }
) {
  // Generate key for the new certificate
  const keys = rsa.generateKeyPair({ bits: 2048 })

  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = Date.now().toString(16)

  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setDate(
    cert.validity.notBefore.getDate() + (options.validityDays || 365)
  )

  // Set subject (different from issuer)
  cert.setSubject([{ shortName: 'CN', value: options.commonName }])

  // Set issuer from CA certificate
  cert.setIssuer(caCert.subject.attributes)

  // Build SAN extension
  const altNames = [{ type: 2, value: options.commonName }]
  if (options.domains) {
    for (const domain of options.domains) {
      altNames.push({ type: 2, value: domain })
    }
  }

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
    },
    {
      name: 'subjectAltName',
      altNames,
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: true,
      authorityCertIssuer: true,
      serialNumber: caCert.serialNumber,
    },
  ])

  // Sign with CA private key
  cert.sign(caKey, sha256.create())

  return {
    certificate: pki.certificateToPem(cert),
    privateKey: pki.privateKeyToPem(keys.privateKey),
    chain: pki.certificateToPem(caCert),
  }
}
```

## Certificate Signing Requests (CSR)

### Create a CSR

```typescript
import { pki, rsa } from 'ts-security'

function createCSR(options: {
  commonName: string
  organization?: string
  country?: string
  domains?: string[]
}) {
  // Generate key pair
  const keys = rsa.generateKeyPair({ bits: 2048 })

  // Create CSR
  const csr = pki.createCertificationRequest()
  csr.publicKey = keys.publicKey

  // Set subject
  const attrs = [{ shortName: 'CN', value: options.commonName }]
  if (options.organization) {
    attrs.push({ shortName: 'O', value: options.organization })
  }
  if (options.country) {
    attrs.push({ shortName: 'C', value: options.country })
  }
  csr.setSubject(attrs)

  // Add SAN extension if multiple domains
  if (options.domains && options.domains.length > 0) {
    csr.setAttributes([
      {
        name: 'extensionRequest',
        extensions: [
          {
            name: 'subjectAltName',
            altNames: options.domains.map(domain => ({
              type: 2,
              value: domain,
            })),
          },
        ],
      },
    ])
  }

  // Sign the CSR
  csr.sign(keys.privateKey, sha256.create())

  return {
    csr: pki.certificationRequestToPem(csr),
    privateKey: pki.privateKeyToPem(keys.privateKey),
  }
}

// Usage
const { csr, privateKey } = createCSR({
  commonName: 'example.com',
  organization: 'My Company',
  country: 'US',
  domains: ['example.com', 'www.example.com'],
})
```

### Process a CSR

```typescript
import { pki } from 'ts-security'

function processCSR(csrPem: string, caCert: any, caKey: any) {
  // Parse the CSR
  const csr = pki.certificationRequestFromPem(csrPem)

  // Verify the CSR signature
  if (!csr.verify()) {
    throw new Error('CSR signature verification failed')
  }

  // Create certificate from CSR
  const cert = pki.createCertificate()
  cert.publicKey = csr.publicKey
  cert.serialNumber = Date.now().toString(16)

  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 1
  )

  // Copy subject from CSR
  cert.setSubject(csr.subject.attributes)
  cert.setIssuer(caCert.subject.attributes)

  // Copy extensions from CSR if present
  const extensionRequest = csr.getAttribute({ name: 'extensionRequest' })
  if (extensionRequest) {
    cert.setExtensions(extensionRequest.extensions)
  }

  // Add standard extensions
  cert.setExtensions([
    ...cert.extensions,
    { name: 'basicConstraints', cA: false },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
    },
  ])

  // Sign with CA key
  cert.sign(caKey, sha256.create())

  return pki.certificateToPem(cert)
}
```

## Certificate Verification

### Verify Certificate Chain

```typescript
import { pki } from 'ts-security'

function verifyCertificateChain(
  certPem: string,
  caCertPem: string
): { valid: boolean; error?: string } {
  try {
    const cert = pki.certificateFromPem(certPem)
    const caCert = pki.certificateFromPem(caCertPem)

    // Create CA store
    const caStore = pki.createCaStore([caCert])

    // Verify
    const verified = pki.verifyCertificateChain(caStore, [cert])

    return { valid: verified }
  } catch (error) {
    return { valid: false, error: error.message }
  }
}
```

### Check Certificate Expiry

```typescript
import { pki } from 'ts-security'

function checkCertificateExpiry(certPem: string): {
  valid: boolean
  daysRemaining: number
  expiresAt: Date
} {
  const cert = pki.certificateFromPem(certPem)
  const now = new Date()
  const expiresAt = cert.validity.notAfter

  const daysRemaining = Math.floor(
    (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  )

  return {
    valid: now >= cert.validity.notBefore && now <= expiresAt,
    daysRemaining,
    expiresAt,
  }
}
```

### Extract Certificate Information

```typescript
import { pki } from 'ts-security'

function getCertificateInfo(certPem: string) {
  const cert = pki.certificateFromPem(certPem)

  // Get subject attributes
  const subject: Record<string, string> = {}
  for (const attr of cert.subject.attributes) {
    subject[attr.shortName || attr.name] = attr.value
  }

  // Get issuer attributes
  const issuer: Record<string, string> = {}
  for (const attr of cert.issuer.attributes) {
    issuer[attr.shortName || attr.name] = attr.value
  }

  // Get SAN extension
  const sanExt = cert.getExtension('subjectAltName')
  const domains: string[] = []
  if (sanExt && sanExt.altNames) {
    for (const alt of sanExt.altNames) {
      if (alt.type === 2) {
        // DNS
        domains.push(alt.value)
      }
    }
  }

  return {
    subject,
    issuer,
    serialNumber: cert.serialNumber,
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
    domains,
    isCA: cert.getExtension('basicConstraints')?.cA || false,
  }
}
```

## Converting Certificate Formats

### PEM to DER

```typescript
import { pki, pem } from 'ts-security'

function pemToDer(pemString: string): Uint8Array {
  const messages = pem.decode(pemString)
  return messages[0].body
}
```

### DER to PEM

```typescript
import { pem } from 'ts-security'

function derToPem(derBytes: Uint8Array, type: string): string {
  return pem.encode({
    type, // e.g., "CERTIFICATE" or "RSA PRIVATE KEY"
    body: derBytes,
  })
}
```

### PKCS#12 (PFX) Export

```typescript
import { pkcs12, pki, asn1 } from 'ts-security'

function exportToPkcs12(
  certPem: string,
  keyPem: string,
  password: string,
  friendlyName?: string
): Uint8Array {
  const cert = pki.certificateFromPem(certPem)
  const key = pki.privateKeyFromPem(keyPem)

  // Create PKCS#12
  const p12Asn1 = pkcs12.toPkcs12Asn1(
    key,
    [cert],
    password,
    {
      friendlyName: friendlyName || 'Certificate',
      algorithm: '3des', // or 'aes128', 'aes192', 'aes256'
    }
  )

  // Convert to DER
  const p12Der = asn1.toDer(p12Asn1)
  return new Uint8Array(p12Der.bytes())
}
```

## Next Steps

- Set up [HTTPS](/guide/https) for your application
- Learn about [X.509 Operations](/guide/x509)
- Review the [PKI API Reference](/api/pki)
