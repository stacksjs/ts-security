import { describe, expect, it } from 'bun:test'
import { pki } from '../src/pki'
import { privateKeyToAsn1, rsa } from 'ts-rsa'
import { asn1 } from 'ts-asn1'

describe('PKI', () => {
  // Sample RSA private key in PEM format
  const samplePrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC5S5glfiQdyf0EYzEn1hXYLzLpWNVjuReMH3RyUYbj5UKaPpTB
hcYsYhCvq0TS+K7FQQEcA9X2iFEY9U6XcqgmO8sTUvL1+g0jMOPjaRYLvT5QKQ9G
ULQm9yxDv5qYWYJAKHKLbsatn0Ro4O9+FQJbgLcjEBaq4GqvVQIUQwECAwEAAQKB
gBYY1KzXYedPXBelIbZT7hDPF6VvdNxV00HrDgEfqjRpjvGXjqQIAEyAdS8hEVXj
GcvPP0PfHFdOIcCDyZ9W8ddNNR+TGlbwaLHdFUlEavLnUY6aGKTfj7LPm5OL8/Xo
QjNJzC7lImC7WV9Mbgxfz3a1dYfO/c2hVi0jNjgvxQkBAkEA7UZjxaFR5p4qMcZI
JVQmj7TrHDBFe+7PqGFQKjnJ1htxe2TgX5iIXkz8P6JE04zWU8Jx5lZRYYP6Tqfw
UQJBAMgvC2i47E/n6Z/K7uZLFtCgl+hfzRzLGNHRXxlhnRQfFUkZlzrYjKkMbLEb
U7EKWAGfLjU7FLZIKmCwkUSXQVUCQHiAKHviVQefwaeT6cNpZIsGhwPftuYGTTtF
Jf6ziYpkKAqYFNoSGGiTvuMqVX9kplDYpBmVkJm2UyZzJBLiCEECQEYtxKnsXUYr
3ClxuCQDON42tNcSxCsTYJ9ZrKxnuXsETKYxBEQ1U6hVCZ1Q1GqBJHsafCOprGVT
3hqp7PXWnTUCQEb6UOLIrKANyNmj5K+wbvQWn/z63EwOF827ZQ2BFTH5vAy0yFGx
xzZXm+2ksrHGiIBs4KnU5b4j3GXdkQkJhSA=
-----END RSA PRIVATE KEY-----`;

  // Sample PrivateKeyInfo in PEM format
  const samplePrivateKeyInfoPem = `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALlLmCV+JB3J/QRj
MSfWFdgvMulY1WO5F4wfdHJRhuPlQpo+lMGFxixiEK+rRNL4rsVBARwD1faIURj1
TpdyqCY7yxNS8vX6DSMw4+NpFgu9PlApD0ZQtCb3LEO/mphZgkAocotuxq2fRGjg
734VAluAtyMQFqrgaq9VAhRDAQIDAQABAoGAFhjUrNdh509cF6UhtlPuEM8XpW90
3FXTQesOAR+qNGmO8ZeOpAgATIB1LyERVeMZy88/Q98cV04hwIPJn1bx1001H5Ma
VvBosf0VSURq8udRjpoYpN+Pss+bk4vz9ehCM0nMLuUiYLtZX0xuDF/PdrV1h879
zaFWLSM2OC/FCQECQQDtRmPFoVHmnioxhkglVCaPtOscMEV77s+oYVAqOcnWG3F7
ZOBfmIheTOw/okTTjNZTwnHmVlFhg/pOp/BRAkEAyC8LeLjsT+frn8ru5ksW0KCX
6F/NHMsY0dFfGWGdFB8VSRmXOtiMqQxssRtTsQpYAZ8uNTsUtkgqYLCRRJdBVQJA
eIAoe+JVB5/Bp5Ppw2lkiwaHA9+25gZNO0Ul/rOJimQoCpgU2hIYaJO+4ypVf2Sm
UNikGZWQmbZTJnMkEuIIQQJARi3EqexdRivcKXG4JAM43ja01xLEKxNgn1msrGe5
ewRMpjEERDVTqFUJnVDUaoEkexp8I6msZVPeGqns9dadNQJARvpQ4sisaA3I2aPk
r7Bu9Baf/PrcTA4XzbtlDYEVMfm8DLTIU7HHNleb7aSyscaIgGzgqdTlviPcZd2R
CQmFIA==
-----END PRIVATE KEY-----`;

  it('should convert a private key from PEM format', () => {
    const privateKey = pki.privateKeyFromPem(samplePrivateKeyPem);

    // Verify the key properties
    expect(privateKey).toBeDefined();
    expect(privateKey.n).toBeDefined(); // Modulus
    expect(privateKey.e).toBeDefined(); // Public exponent
    expect(privateKey.d).toBeDefined(); // Private exponent
    expect(privateKey.p).toBeDefined(); // Prime 1
    expect(privateKey.q).toBeDefined(); // Prime 2
    expect(privateKey.dP).toBeDefined(); // Exponent 1
    expect(privateKey.dQ).toBeDefined(); // Exponent 2
    expect(privateKey.qInv).toBeDefined(); // Coefficient
  });

  it('should convert a private key to PEM format', () => {
    // First, parse a private key from PEM
    const privateKey = pki.privateKeyFromPem(samplePrivateKeyPem);

    // Then convert it back to PEM
    const pemOutput = pki.privateKeyToPem(privateKey, 64);

    // Verify the output is a valid PEM string
    expect(pemOutput).toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(pemOutput).toContain('-----END RSA PRIVATE KEY-----');

    // Parse the output again to verify it's valid
    const parsedAgain = pki.privateKeyFromPem(pemOutput);
    expect(parsedAgain).toBeDefined();

    // Verify key components match
    expect(parsedAgain.n.toString()).toBe(privateKey.n.toString());
    expect(parsedAgain.e.toString()).toBe(privateKey.e.toString());
    expect(parsedAgain.d.toString()).toBe(privateKey.d.toString());
  });

  it('should convert a PrivateKeyInfo to PEM format', () => {
    // First, parse a private key from PEM
    const privateKey = pki.privateKeyFromPem(samplePrivateKeyPem);

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
          value: new Uint8Array([0]) // Version 0
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
              value: asn1.oidToDer('1.2.840.113549.1.1.1') // rsaEncryption
            },
            {
              tagClass: asn1.Class.UNIVERSAL,
              type: asn1.Type.NULL,
              constructed: false,
              value: ''
            }
          ]
        },
        {
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.OCTETSTRING,
          constructed: false,
          value: asn1.toDer(privateKeyToAsn1(privateKey)).getBytes()
        }
      ]
    };

    // Convert to PEM
    const pemOutput = pki.privateKeyInfoToPem(privateKeyInfo, 64);

    // Verify the output is a valid PEM string
    expect(pemOutput).toContain('-----BEGIN PRIVATE KEY-----');
    expect(pemOutput).toContain('-----END PRIVATE KEY-----');
  });

  it('should throw an error for invalid PEM header type', () => {
    const invalidPem = `-----BEGIN CERTIFICATE-----
MIICXAIBAAKBgQC5S5glfiQdyf0EYzEn1hXYLzLpWNVjuReMH3RyUYbj5UKaPpTB
hcYsYhCvq0TS+K7FQQEcA9X2iFEY9U6XcqgmO8sTUvL1+g0jMOPjaRYLvT5QKQ9G
ULQm9yxDv5qYWYJAKHKLbsatn0Ro4O9+FQJbgLcjEBaq4GqvVQIUQwECAwEAAQ==
-----END CERTIFICATE-----`;

    expect(() => {
      pki.privateKeyFromPem(invalidPem);
    }).toThrow(/PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY"/);
  });

  it('should throw an error for encrypted PEM', () => {
    const encryptedPem = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,FFFFFFFFFFFFFFFF

MIICXAIBAAKBgQC5S5glfiQdyf0EYzEn1hXYLzLpWNVjuReMH3RyUYbj5UKaPpTB
hcYsYhCvq0TS+K7FQQEcA9X2iFEY9U6XcqgmO8sTUvL1+g0jMOPjaRYLvT5QKQ9G
ULQm9yxDv5qYWYJAKHKLbsatn0Ro4O9+FQJbgLcjEBaq4GqvVQIUQwECAwEAAQ==
-----END RSA PRIVATE KEY-----`;

    expect(() => {
      pki.privateKeyFromPem(encryptedPem);
    }).toThrow(/PEM is encrypted/);
  });
});


