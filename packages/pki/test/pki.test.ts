import { describe, expect, it } from 'bun:test'
import { asn1 } from 'ts-asn1'
import { privateKeyToAsn1 } from 'ts-rsa'
import { pki } from '../src/pki'

describe('PKI', () => {
  // Sample RSA private key in PEM format (PKCS#1)
  const samplePrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDH9HsHPKpvNYlRXbwQGiga94pMSUScjG1PM3bjib2/L318NajM
WPFmRbdsZKAOyFuBuqqrutAtD2bW6SdlgYyYnjYTKCjj3PkLhjQ3to2wXFkHHQw0
2vTHAqOmtAVgGIjrpa49pyUoKNjNM6yWBNx/PszEqazmdfLX7EKOL37BIQIDAQAB
AoGACy3P8wehP7Zuhu4GpZ/QvjE4uiseeuIe+l6WNwJsaVPuYBNf7IzMcjtTlevK
RwlMlGQrRo6bNOm3hixi13n2sjhY4ms9cq1IvgJ4CwgITFgEbXx3K1Q8cqm7Y1cH
fSOiPPPi3cp3Dp+B3mFFt95gpRmeztPFk9Z+Y/tWIkq1bwECQQDmGnvAZLuOUC/p
Wd8Rf2ceq3e5b4Qq+dG2L0jA4VZ/zwOSvllIzslUriK9btyzrGvFw5Xkxa8i9UmX
Rp1ZKqD1AkEA3nVjsY6kwz3eLuAcRc0kU/ttyiJLR3jMn1DMdA+fvIrp4cMPCQm3
zWzFEnYZK7O+6avOcv0K4e0sZQvB042T/QJBAOYYr405bfAmsXJ4gz8dFoIt1uAg
6pqLDDFRYUA3VWcjHKCeJexPlDZQl760YJBvJ6owJfEJ2VNs0zUp0Oi8Xw0CQAY3
8dl8y05J5HQa/69T1LgkRyVnYANXdSDe+VglN6nlmDQfZ8Qw6Vpst/WUJ4/5LlUJ
4HOGb09xedQ5R+nKA2ECQAcBKdS7dRRo+/UoQHqJe2nFF0dM0fZyNBoaEOzsa706
6FF0ENMECmzapQOjqk0hYzbgwlOJza1wt5wiuP1PPLA=
-----END RSA PRIVATE KEY-----`

  it('should convert a private key from PEM format', () => {
    const privateKey = pki.privateKeyFromPem(samplePrivateKeyPem)

    // Verify the key properties
    expect(privateKey).toBeDefined()
    expect(privateKey.n).toBeDefined() // Modulus
    expect(privateKey.e).toBeDefined() // Public exponent
    expect(privateKey.d).toBeDefined() // Private exponent
    expect(privateKey.p).toBeDefined() // Prime 1
    expect(privateKey.q).toBeDefined() // Prime 2
    expect(privateKey.dP).toBeDefined() // Exponent 1
    expect(privateKey.dQ).toBeDefined() // Exponent 2
    expect(privateKey.qInv).toBeDefined() // Coefficient
  })

  it('should convert a private key to PEM format', () => {
    // First, parse a private key from PEM
    const privateKey = pki.privateKeyFromPem(samplePrivateKeyPem)

    // Then convert it back to PEM
    const pemOutput = pki.privateKeyToPem(privateKey, 64)

    // Verify the output is a valid PEM string
    expect(pemOutput).toContain('-----BEGIN RSA PRIVATE KEY-----')
    expect(pemOutput).toContain('-----END RSA PRIVATE KEY-----')

    // Parse the output again to verify it's valid
    const parsedAgain = pki.privateKeyFromPem(pemOutput)
    expect(parsedAgain).toBeDefined()

    // Verify key components match
    expect(parsedAgain.n.toString()).toBe(privateKey.n.toString())
    expect(parsedAgain.e.toString()).toBe(privateKey.e.toString())
    expect(parsedAgain.d.toString()).toBe(privateKey.d.toString())
  })

  it('should convert a PrivateKeyInfo to PEM format', () => {
    // First, parse a private key from PEM
    const privateKey = pki.privateKeyFromPem(samplePrivateKeyPem)

    // Create a PrivateKeyInfo ASN.1 object
    const privateKeyInfo = {
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [
        {
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.INTEGER,
          constructed: false,
          value: new Uint8Array([0]), // Version 0
        },
        {
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.SEQUENCE,
          constructed: true,
          value: [
            {
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.OID,
              constructed: false,
              value: asn1.oidToDer('1.2.840.113549.1.1.1'), // rsaEncryption
            },
            {
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.NULL,
              constructed: false,
              value: '',
            },
          ],
        },
        {
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.OCTETSTRING,
          constructed: false,
          value: asn1.toDer(privateKeyToAsn1(privateKey)).getBytes(),
        },
      ],
    }

    // Convert to PEM
    const pemOutput = pki.privateKeyInfoToPem(privateKeyInfo, 64)

    // Verify the output is a valid PEM string
    expect(pemOutput).toContain('-----BEGIN PRIVATE KEY-----')
    expect(pemOutput).toContain('-----END PRIVATE KEY-----')
  })

  it('should throw an error for invalid PEM header type', () => {
    const invalidPem = `-----BEGIN CERTIFICATE-----
MIICXAIBAAKBgQC5S5glfiQdyf0EYzEn1hXYLzLpWNVjuReMH3RyUYbj5UKaPpTB
hcYsYhCvq0TS+K7FQQEcA9X2iFEY9U6XcqgmO8sTUvL1+g0jMOPjaRYLvT5QKQ9G
ULQm9yxDv5qYWYJAKHKLbsatn0Ro4O9+FQJbgLcjEBaq4GqvVQIUQwECAwEAAQ==
-----END CERTIFICATE-----`

    expect(() => {
      pki.privateKeyFromPem(invalidPem)
    }).toThrow(/PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY"/)
  })

  it('should throw an error for encrypted PEM', () => {
    const encryptedPem = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,FFFFFFFFFFFFFFFF

MIICXAIBAAKBgQC5S5glfiQdyf0EYzEn1hXYLzLpWNVjuReMH3RyUYbj5UKaPpTB
hcYsYhCvq0TS+K7FQQEcA9X2iFEY9U6XcqgmO8sTUvL1+g0jMOPjaRYLvT5QKQ9G
ULQm9yxDv5qYWYJAKHKLbsatn0Ro4O9+FQJbgLcjEBaq4GqvVQIUQwECAwEAAQ==
-----END RSA PRIVATE KEY-----`

    expect(() => {
      pki.privateKeyFromPem(encryptedPem)
    }).toThrow(/PEM is encrypted/)
  })
})
