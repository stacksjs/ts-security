import { asn1 } from 'ts-asn1'
import { decode, encode, pem } from 'ts-pem'
import { rsa } from 'ts-rsa'
import { createBuffer } from 'ts-security-utils'

interface CustomError extends Error {
  headerType?: string
}

/**
 * Converts an RSA private key from PEM format.
 *
 * @param pem the PEM-formatted private key.
 *
 * @return the private key.
 */
export function privateKeyFromPem(pem: string): any {
  const msg = decode(pem)[0]

  if (msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    const error: CustomError = new Error('Could not convert private key from PEM; PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".')
    error.headerType = msg.type
    throw error
  }

  if (msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert private key from PEM; PEM is encrypted.')
  }

  // convert DER to ASN.1 object
  const obj = asn1.fromDer(createBuffer(msg.body))

  return rsa.privateKeyFromAsn1(obj)
};

/**
 * Converts an RSA private key to PEM format.
 *
 * @param key the private key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
export function privateKeyToPem(key: any, maxline: number): string {
  // convert to ASN.1, then DER, then PEM-encode
  const msg = {
    type: 'RSA PRIVATE KEY',
    body: new TextEncoder().encode(asn1.toDer(rsa.privateKeyToAsn1(key)).getBytes()),
    procType: null,
    contentDomain: null,
    dekInfo: null,
    headers: [],
  }

  return pem.encode(msg, { maxline })
};

/**
 * Converts a PrivateKeyInfo to PEM format.
 *
 * @param pki the PrivateKeyInfo.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
export function privateKeyInfoToPem(pki: any, maxline: number): string {
  // convert to DER, then PEM-encode
  const msg = {
    type: 'PRIVATE KEY',
    body: new TextEncoder().encode(asn1.toDer(pki).getBytes()),
    procType: null,
    contentDomain: null,
    dekInfo: null,
    headers: [],
  }

  return encode(msg, { maxline })
};

export interface PKI {
  privateKeyFromPem: typeof privateKeyFromPem
  privateKeyToPem: typeof privateKeyToPem
  privateKeyInfoToPem: typeof privateKeyInfoToPem
}

export const pki: PKI = {
  privateKeyFromPem,
  privateKeyToPem,
  privateKeyInfoToPem,
}

export default pki
