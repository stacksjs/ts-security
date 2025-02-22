/**
 * Password-Based Key-Derivation Function #2 implementation.
 *
 * See RFC 2898 for details.
 *
 * @author Dave Longley
 * @author Chris Breuer
 */

import type { MessageDigest } from './sha1'
import { hmac } from './hmac'
import { sha1 } from './sha1'
import { int32ToBytes, isServer, xorBytes } from './utils'

let crypto: typeof import('node:crypto') | undefined
if (isServer) {
  crypto = require('node:crypto')
}

const hashAlgorithms: { [key: string]: { create: () => MessageDigest } } = {
  sha1: { create: () => sha1.create() },
}

/**
 * Derives a key from a password.
 *
 * @param p the password as a binary-encoded string of bytes.
 * @param s the salt as a binary-encoded string of bytes.
 * @param c the iteration count, a positive integer.
 * @param dkLen the intended length, in bytes, of the derived key, (max: 2^32 - 1) * hash length of the PRF.
 * @param [md] the message digest (or algorithm identifier as a string) to use in the PRF, defaults to SHA-1.
 * @param [callback(err, key)] presence triggers asynchronous version, called once the operation completes.
 *
 * @return the derived key, as a binary-encoded string of bytes, for the synchronous version (if no callback is specified).
 */
export function pbkdf2(
  p: Buffer,
  s: Buffer,
  c: number,
  dkLen: number,
  md?: MessageDigest | string | ((err: Error | null, key?: string) => void),
  callback?: (err: Error | null, key?: string) => void,
): string | void {
  if (typeof md === 'function') {
    callback = md
    md = undefined
  }

  // use native implementation if possible and not disabled, note that
  // some node versions only support SHA-1, others allow digest to be changed
  if (isServer && crypto?.pbkdf2 && (md === undefined || typeof md !== 'object')
    && (crypto.pbkdf2Sync.length > 4 || (!md || md === 'sha1'))) {
    if (typeof md !== 'string') {
      // default prf to SHA-1
      md = 'sha1'
    }
    const pBuf = Buffer.from(p)
    const sBuf = Buffer.from(s)
    if (!callback) {
      if (crypto.pbkdf2Sync.length === 4) {
        return crypto.pbkdf2Sync(pBuf, sBuf, c, dkLen, md).toString('binary')
      }
      return crypto.pbkdf2Sync(pBuf, sBuf, c, dkLen, md).toString('binary')
    }

    return crypto.pbkdf2(pBuf, sBuf, c, dkLen, md, (err: Error | null, key: Buffer) => {
      if (err) {
        return callback!(err)
      }
      callback!(null, key.toString('binary'))
    })
  }

  if (typeof md === 'undefined' || md === null) {
    // default prf to SHA-1
    md = 'sha1'
  }

  let hashAlgorithm: MessageDigest
  if (typeof md === 'string') {
    // look up message digest
    if (!(md in hashAlgorithms)) {
      throw new Error(`Unknown hash algorithm: ${md}`)
    }
    hashAlgorithm = hashAlgorithms[md].create()
  }
  else {
    hashAlgorithm = md
  }

  const hLen = hashAlgorithm.digestLength

  /* 1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
    stop. */
  if (dkLen > (0xFFFFFFFF * hLen)) {
    const err = new Error('Derived key is too long.')
    if (callback) {
      return callback(err)
    }
    throw err
  }

  /* 2. Let len be the number of hLen-octet blocks in the derived key,
    rounding up, and let r be the number of octets in the last
    block:

    len = CEIL(dkLen / hLen),
    r = dkLen - (len - 1) * hLen. */
  const len = Math.ceil(dkLen / hLen)
  const r = dkLen - (len - 1) * hLen

  /* 3. For each block of the derived key apply the function F defined
    below to the password P, the salt S, the iteration count c, and
    the block index to compute the block:

    T_1 = F(P, S, c, 1),
    T_2 = F(P, S, c, 2),
    ...
    T_len = F(P, S, c, len),

    where the function F is defined as the exclusive-or sum of the
    first c iterates of the underlying pseudorandom function PRF
    applied to the password P and the concatenation of the salt S
    and the block index i:

    F(P, S, c, i) = u_1 XOR u_2 XOR ... XOR u_c

    where

    u_1 = PRF(P, S || INT(i)),
    u_2 = PRF(P, u_1),
    ...
    u_c = PRF(P, u_{c-1}).

    Here, INT(i) is a four-octet encoding of the integer i, most
    significant octet first. */
  const prf = hmac.create()
  prf.start(hashAlgorithm, p)
  let dk = ''
  let xor: string, u_c: string, u_c1: string

  // sync version
  if (!callback) {
    for (let i = 1; i <= len; ++i) {
      // PRF(P, S || INT(i)) (first iteration)
      prf.start(hashAlgorithm, p)
      prf.update(s)
      prf.update(int32ToBytes(i))
      xor = u_c1 = prf.digest().getBytes()

      // PRF(P, u_{c-1}) (other iterations)
      for (let j = 2; j <= c; ++j) {
        prf.start(hashAlgorithm, p)
        prf.update(u_c1)
        u_c = prf.digest().getBytes()
        // F(p, s, c, i)
        xor = xorBytes(xor, u_c, hLen)
        u_c1 = u_c
      }

      /* 4. Concatenate the blocks and extract the first dkLen octets to
        produce a derived key DK:

        DK = T_1 || T_2 ||  ...  || T_len<0..r-1> */
      dk += (i < len) ? xor : xor.substr(0, r)
    }
    /* 5. Output the derived key DK. */
    return dk
  }

  // async version
  let i = 1
  let j: number
  function outer() {
    if (i > len) {
      // done
      return callback!(null, dk)
    }

    // PRF(P, S || INT(i)) (first iteration)
    prf.start(hashAlgorithm, p)
    prf.update(s)
    prf.update(int32ToBytes(i))
    xor = u_c1 = prf.digest().getBytes()

    // PRF(P, u_{c-1}) (other iterations)
    j = 2
    inner()
  }

  function inner() {
    if (j <= c) {
      prf.start(hashAlgorithm, p)
      prf.update(u_c1)
      u_c = prf.digest().getBytes()
      // F(p, s, c, i)
      xor = xorBytes(xor, u_c, hLen)
      u_c1 = u_c
      ++j

      return setImmediate(inner)
    }

    /* 4. Concatenate the blocks and extract the first dkLen octets to
      produce a derived key DK:

      DK = T_1 || T_2 ||  ...  || T_len<0..r-1> */
    dk += (i < len) ? xor : xor.substr(0, r)

    ++i
    outer()
  }

  outer()
}

export function pbkdf2Sync(p: Buffer, s: Buffer, c: number, dkLen: number, md?: MessageDigest | string): string {
  return pbkdf2(p, s, c, dkLen, md) as string
}

export interface Pkcs5 {
  pbkdf2: typeof pbkdf2
  pbkdf2Sync: typeof pbkdf2Sync
}

export const pkcs5: Pkcs5 = {
  pbkdf2,
  pbkdf2Sync,
}
