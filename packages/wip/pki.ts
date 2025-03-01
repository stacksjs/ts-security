import type { RSA } from './algorithms/asymmetric/rsa'
import { privateKeyFromAsn1, privateKeyToAsn1, rsa } from './algorithms/asymmetric/rsa'
import { asn1 } from './encoding/asn1'
import { pem } from './encoding/pem'
import { certificateExtensionsToAsn1, certificateFromPem, certificateToAsn1, CRIAttributesAsArray, getCertificationRequestInfo } from './x509'

/**
 * TypeScript implementation of a basic Public Key Infrastructure, including
 * support for RSA public and private keys.
 *
 * @author Dave Longley
 * @author Chris Breuer
 */

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
export function privateKeyFromPem(pemString: string): any {
  const msg = pem.decode(pemString)[0]

  if (msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    const error: CustomError = new Error('Could not convert private key from PEM; PEM header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".')
    error.headerType = msg.type
    throw error
  }

  if (msg.procType && msg.procType.type === 'ENCRYPTED')
    throw new Error('Could not convert private key from PEM; PEM is encrypted.')

  // convert DER to ASN.1 object
  const obj = asn1.fromDer(msg.body)

  return privateKeyFromAsn1(obj)
}

/**
 * Converts an RSA private key to PEM format.
 *
 * @param key the private key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
export function privateKeyToPem(key: any, maxline: number = 64): string {
  // convert to ASN.1, then DER, then PEM-encode
  const msg = {
    type: 'RSA PRIVATE KEY',
    body: asn1.toDer(privateKeyToAsn1(key)).getBytes(),
  }

  return pem.encode(msg, { maxline })
}

/**
 * Converts a PrivateKeyInfo to PEM format.
 *
 * @param pki the PrivateKeyInfo.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
export function privateKeyInfoToPem(pki: any, maxline: number = 64): string {
  // convert to DER, then PEM-encode
  const msg = {
    type: 'PRIVATE KEY',
    body: asn1.toDer(pki).getBytes(),
  }

  return pem.encode(msg, { maxline })
}

export interface PKI {
  certificateFromPem: typeof certificateFromPem
  certificateExtensionsToAsn1: typeof certificateExtensionsToAsn1
  certificateToAsn1: typeof certificateToAsn1
  CRIAttributesAsArray: typeof CRIAttributesAsArray
  getCertificationRequestInfo: typeof getCertificationRequestInfo
  privateKeyFromPem: typeof privateKeyFromPem
  privateKeyToPem: typeof privateKeyToPem
  privateKeyInfoToPem: typeof privateKeyInfoToPem
  rsa: RSA
}

export const pki: PKI = {
  certificateFromPem,
  certificateExtensionsToAsn1,
  certificateToAsn1,
  getCertificationRequestInfo,
  CRIAttributesAsArray,
  privateKeyFromPem,
  privateKeyToPem,
  privateKeyInfoToPem,
  rsa,
}

export default pki
