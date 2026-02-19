/**
 * Partial implementation of PKCS#1 v2.2: RSA-OEAP
 *
 * Modified but based on the following MIT and BSD licensed code:
 *
 * https://github.com/kjur/jsjws/blob/master/rsa.js:
 *
 * The 'jsjws'(JSON Web Signature JavaScript Library) License
 *
 * Copyright (c) 2012 Kenji Urushima
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * http://webrsa.cvs.sourceforge.net/viewvc/webrsa/Client/RSAES-OAEP.js?content-type=text%2Fplain:
 *
 * RSAES-OAEP.js
 * $Id: RSAES-OAEP.js,v 1.1.1.1 2003/03/19 15:37:20 ellispritchard Exp $
 * JavaScript Implementation of PKCS #1 v2.1 RSA CRYPTOGRAPHY STANDARD (RSA Laboratories, June 14, 2002)
 * Copyright (C) Ellis Pritchard, Guardian Unlimited 2003.
 * Contact: ellis@nukinetics.com
 * Distributed under the BSD License.
 *
 * Official documentation: http://www.rsa.com/rsalabs/node.asp?id=2125
 *
 * @author Evan Jones (http://evanjones.ca/)
 * @author Dave Longley
 * @author Chris Breuer
 */

import type { ByteStringBuffer } from 'ts-security-utils'
import { sha1 } from '@stacksjs/ts-hash'

// Extended Error interface for PKCS1 specific errors
interface PKCS1Error extends Error {
  length?: number
  maxLength?: number
  seedLength?: number
  digestLength?: number
  expectedLength?: number
}

// Type definitions for key and options
interface RSAKey {
  n: {
    bitLength: () => number
  }
}

interface MessageDigest {
  start: () => void
  update: (msg: string, encoding?: string) => void
  digest: () => ByteStringBuffer
  digestLength: number
}

interface PKCS1Options {
  label?: string
  seed?: string
  md?: MessageDigest
  mgf1?: {
    md?: MessageDigest
  }
}

// Utility functions that were previously from forge
function getRandomBytes(count: number): string {
  const bytes = new Uint8Array(count)
  crypto.getRandomValues(bytes)
  return Array.from(bytes).map(b => String.fromCharCode(b)).join('')
}

function xorBytes(a: string, b: string, length: number): string {
  let result = ''
  for (let i = 0; i < length; i++) {
    result += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i))
  }
  return result
}

/**
 * Encode the given RSAES-OAEP message (M) using key, with optional label (L)
 * and seed.
 *
 * This method does not perform RSA encryption, it only encodes the message
 * using RSAES-OAEP.
 *
 * @param key the RSA key to use.
 * @param message the message to encode.
 * @param options the options to use:
 *          label an optional label to use.
 *          seed the seed to use.
 *          md the message digest object to use, undefined for SHA-1.
 *          mgf1 optional mgf1 parameters:
 *            md the message digest object to use for MGF1.
 *
 * @return the encoded message bytes.
 */
export function encode_rsa_oaep(key: RSAKey, message: string, options: PKCS1Options | string): string {
  // parse arguments
  let label: string | undefined
  let seed: string | undefined
  let md: MessageDigest | undefined
  let mgf1Md: MessageDigest | undefined

  // legacy args (label, seed, md)
  if (typeof options === 'string') {
    label = options
    seed = arguments[3] as string
    md = arguments[4] as MessageDigest
  }
  else if (options) {
    label = options.label
    seed = options.seed
    md = options.md
    if (options.mgf1?.md) {
      mgf1Md = options.mgf1.md
    }
  }

  // default OAEP to SHA-1 message digest
  if (!md) {
    md = sha1.create()
  }
  else {
    md.start()
  }

  // default MGF-1 to same as OAEP
  if (!mgf1Md) {
    mgf1Md = md
  }

  // compute length in bytes and check output
  const keyLength = Math.ceil(key.n.bitLength() / 8)
  const maxLength = keyLength - 2 * md.digestLength - 2
  if (message.length > maxLength) {
    const error = new Error('RSAES-OAEP input message length is too long.') as PKCS1Error
    error.length = message.length
    error.maxLength = maxLength
    throw error
  }

  if (!label) {
    label = ''
  }
  md.update(label, 'raw')
  const lHash = md.digest()

  let PS = ''
  const PS_length = maxLength - message.length
  for (let i = 0; i < PS_length; i++) {
    PS += '\x00'
  }

  const DB = `${lHash.getBytes() + PS}\x01${message}`

  if (!seed) {
    seed = getRandomBytes(md.digestLength)
  }
  else if (seed.length !== md.digestLength) {
    const error = new Error('Invalid RSAES-OAEP seed. The seed length must match the digest length.') as PKCS1Error
    error.seedLength = seed.length
    error.digestLength = md.digestLength
    throw error
  }

  const dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, mgf1Md)
  const maskedDB = xorBytes(DB, dbMask, DB.length)

  const seedMask = rsa_mgf1(maskedDB, md.digestLength, mgf1Md)
  const maskedSeed = xorBytes(seed, seedMask, seed.length)

  // return encoded message
  return `\x00${maskedSeed}${maskedDB}`
}

/**
 * Decode the given RSAES-OAEP encoded message (EM) using key, with optional
 * label (L).
 *
 * This method does not perform RSA decryption, it only decodes the message
 * using RSAES-OAEP.
 *
 * @param key the RSA key to use.
 * @param em the encoded message to decode.
 * @param options the options to use:
 *          label an optional label to use.
 *          md the message digest object to use for OAEP, undefined for SHA-1.
 *          mgf1 optional mgf1 parameters:
 *            md the message digest object to use for MGF1.
 *
 * @return the decoded message bytes.
 */
export function decode_rsa_oaep(key: RSAKey, em: string, options: PKCS1Options | string): string {
  // parse args
  let label: string | undefined
  let md: MessageDigest | undefined
  let mgf1Md: MessageDigest | undefined

  // legacy args
  if (typeof options === 'string') {
    label = options
    md = arguments[3] as MessageDigest
  }
  else if (options) {
    label = options.label
    md = options.md
    if (options.mgf1?.md) {
      mgf1Md = options.mgf1.md
    }
  }

  // compute length in bytes
  const keyLength = Math.ceil(key.n.bitLength() / 8)

  if (em.length !== keyLength) {
    const error = new Error('RSAES-OAEP encoded message length is invalid.') as PKCS1Error
    error.length = em.length
    error.expectedLength = keyLength
    throw error
  }

  // default OAEP to SHA-1 message digest
  if (md === undefined) {
    md = sha1.create()
  }
  else {
    md.start()
  }

  // default MGF-1 to same as OAEP
  if (!mgf1Md) {
    mgf1Md = md
  }

  if (keyLength < 2 * md.digestLength + 2) {
    throw new Error('RSAES-OAEP key is too short for the hash function.')
  }

  if (!label) {
    label = ''
  }

  md.update(label, 'raw')
  const lHash = md.digest().getBytes()

  // split the message into its parts
  const y = em.charAt(0)
  const maskedSeed = em.substring(1, md.digestLength + 1)
  const maskedDB = em.substring(1 + md.digestLength)

  const seedMask = rsa_mgf1(maskedDB, md.digestLength, mgf1Md)
  const seed = xorBytes(maskedSeed, seedMask, maskedSeed.length)

  const dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, mgf1Md)
  const db = xorBytes(maskedDB, dbMask, maskedDB.length)

  const lHashPrime = db.substring(0, md.digestLength)

  // constant time check that all values match what is expected
  let error = 0

  // constant time check y is 0
  error |= y.charCodeAt(0)

  // constant time check lHash vs lHashPrime
  for (let i = 0; i < md.digestLength; ++i) {
    error |= lHash.charCodeAt(i) ^ lHashPrime.charCodeAt(i)
  }

  // "constant time" find the 0x1 byte separating the padding (zeros) from the message
  let in_ps = 1
  let index = md.digestLength
  for (let j = md.digestLength; j < db.length; j++) {
    const code = db.charCodeAt(j)
    const is_0 = (code & 0x1) ^ 0x1
    error |= in_ps & (code & 0xFFFE)
    in_ps = in_ps & is_0
    index += in_ps
  }

  if (error || db.charCodeAt(index) !== 0x1) {
    throw new Error('Invalid RSAES-OAEP padding.')
  }

  return db.substring(index + 1)
}

/**
 * MGF1 using the given hash function to generate a mask of the specified length.
 */
function rsa_mgf1(seed: string, maskLength: number, hash: MessageDigest): string {
  // default to SHA-1 message digest
  if (!hash) {
    hash = sha1.create()
  }
  let t = ''
  const count = Math.ceil(maskLength / hash.digestLength)
  for (let i = 0; i < count; ++i) {
    const c = String.fromCharCode(
      (i >> 24) & 0xFF,
      (i >> 16) & 0xFF,
      (i >> 8) & 0xFF,
      i & 0xFF,
    )
    hash.start()
    hash.update(seed + c)
    t += hash.digest().getBytes()
  }
  return t.substring(0, maskLength)
}

export interface PKCS1 {
  encode_rsa_oaep: (key: RSAKey, message: string, options: PKCS1Options | string) => string
  decode_rsa_oaep: (key: RSAKey, em: string, options: PKCS1Options | string) => string
  rsa_mgf1: (seed: string, maskLength: number, hash: MessageDigest) => string
}

export const pkcs1: PKCS1 = {
  encode_rsa_oaep,
  decode_rsa_oaep,
  rsa_mgf1,
}

export default pkcs1
