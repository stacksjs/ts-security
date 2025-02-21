/**
 * JavaScript implementation of Ed25519.
 *
 * Copyright (c) 2017-2019 Digital Bazaar, Inc.
 *
 * This implementation is based on the most excellent TweetNaCl which is
 * in the public domain. Many thanks to its contributors:
 *
 * https://github.com/dchest/tweetnacl-js
 */

import { getBytesSync } from './random'
import { ByteBuffer } from './utils'
import { asn1 } from './asn1'
import { asn1Validator } from './asn1-validator'
import { oids } from './oids'
import { sha512 as sha } from './sha512'

const publicKeyValidator = asn1Validator.publicKeyValidator
const privateKeyValidator = asn1Validator.privateKeyValidator

const NativeBuffer = typeof Buffer === 'undefined' ? Uint8Array : Buffer

type GF = Float64Array & { __gf?: never }

function gf(init?: number[]): GF {
  const r = new Float64Array(16) as GF
  if (init) {
    for (let i = 0; i < init.length; ++i) {
      r[i] = init[i]
    }
  }
  return r
}

interface Ed25519Constants {
  PUBLIC_KEY_BYTE_LENGTH: number
  PRIVATE_KEY_BYTE_LENGTH: number
  SEED_BYTE_LENGTH: number
  SIGN_BYTE_LENGTH: number
  HASH_BYTE_LENGTH: number
}

interface Ed25519KeyPair {
  publicKey: Buffer | Uint8Array
  privateKey: Buffer | Uint8Array
}

interface Ed25519Options {
  message?: string | Uint8Array | Buffer | typeof ByteBuffer
  privateKey?: string | Uint8Array | Buffer | typeof ByteBuffer
  publicKey?: string | Uint8Array | Buffer | typeof ByteBuffer
  signature?: string | Uint8Array | Buffer | typeof ByteBuffer
  seed?: string | Uint8Array | Buffer
  md?: any
  encoding?: 'binary' | 'utf8'
}

interface Ed25519 {
  constants: Ed25519Constants
  generateKeyPair: (options?: Ed25519Options) => Ed25519KeyPair
  privateKeyFromAsn1: (obj: any) => { privateKeyBytes: Buffer | Uint8Array }
  publicKeyFromAsn1: (obj: any) => Buffer | Uint8Array
  publicKeyFromPrivateKey: (options: Ed25519Options) => Buffer | Uint8Array
  sign: (options: Ed25519Options) => Buffer | Uint8Array
  verify: (options: Ed25519Options) => boolean
}

interface ExtendedError extends Error {
  errors?: any[]
}

const ed25519 = {} as Ed25519

ed25519.constants = {
  PUBLIC_KEY_BYTE_LENGTH: 32,
  PRIVATE_KEY_BYTE_LENGTH: 64,
  SEED_BYTE_LENGTH: 32,
  SIGN_BYTE_LENGTH: 64,
  HASH_BYTE_LENGTH: 64,
}

ed25519.generateKeyPair = function (options) {
  options = options || {}
  let seed = options.seed
  if (seed === undefined) {
    // generate seed
    seed = getBytesSync(ed25519.constants.SEED_BYTE_LENGTH)
  }
  else if (typeof seed === 'string') {
    if (seed.length !== ed25519.constants.SEED_BYTE_LENGTH) {
      throw new TypeError(
        `"seed" must be ${ed25519.constants.SEED_BYTE_LENGTH
        } bytes in length.`,
      )
    }
  }
  else if (!(seed instanceof Uint8Array)) {
    throw new TypeError(
      '"seed" must be a node.js Buffer, Uint8Array, or a binary string.',
    )
  }

  seed = messageToNativeBuffer({ message: seed, encoding: 'binary' })

  const pk = new NativeBuffer(ed25519.constants.PUBLIC_KEY_BYTE_LENGTH)
  const sk = new NativeBuffer(ed25519.constants.PRIVATE_KEY_BYTE_LENGTH)
  for (let i = 0; i < 32; ++i) {
    sk[i] = seed[i]
  }
  crypto_sign_keypair(pk, sk)
  return { publicKey: pk, privateKey: sk }
}

/**
 * Converts a private key from a RFC8410 ASN.1 encoding.
 *
 * @param obj - The asn1 representation of a private key.
 *
 * @returns {object} keyInfo - The key information.
 * @returns {Buffer|Uint8Array} keyInfo.privateKeyBytes - 32 private key bytes.
 */
ed25519.privateKeyFromAsn1 = function (obj: any) {
  const capture = {} as { privateKeyOid?: string, privateKey?: string }
  const errors: any[] = []
  const valid = asn1.validate(obj, privateKeyValidator, capture, errors)
  if (!valid) {
    const error = new Error('Invalid Key.') as ExtendedError
    error.errors = errors
    throw error
  }
  const oid = asn1.derToOid(capture.privateKeyOid)
  const ed25519Oid = oids.EdDSA25519
  if (oid !== ed25519Oid) {
    throw new Error(`Invalid OID "${oid}"; OID must be "${ed25519Oid}".`)
  }
  const privateKey = capture.privateKey
  const privateKeyBytes = messageToNativeBuffer({
    message: asn1.fromDer(privateKey).value,
    encoding: 'binary',
  })
  return { privateKeyBytes }
}

/**
 * Converts a public key from a RFC8410 ASN.1 encoding.
 *
 * @param obj - The asn1 representation of a public key.
 *
 * @return {Buffer|Uint8Array} - 32 public key bytes.
 */
ed25519.publicKeyFromAsn1 = function (obj: any): Buffer | Uint8Array {
  const capture = {} as { publicKeyOid?: string, ed25519PublicKey?: Uint8Array }
  const errors: any[] = []
  const valid = asn1.validate(obj, publicKeyValidator, capture, errors)
  if (!valid) {
    const error = new Error('Invalid Key.') as ExtendedError
    error.errors = errors
    throw error
  }
  const oid = asn1.derToOid(capture.publicKeyOid)
  const ed25519Oid = oids.EdDSA25519
  if (oid !== ed25519Oid) {
    throw new Error(`Invalid OID "${oid}"; OID must be "${ed25519Oid}".`)
  }
  const publicKeyBytes = capture.ed25519PublicKey
  if (!publicKeyBytes || publicKeyBytes.length !== ed25519.constants.PUBLIC_KEY_BYTE_LENGTH) {
    throw new Error('Key length is invalid.')
  }

  return messageToNativeBuffer({
    message: publicKeyBytes,
    encoding: 'binary',
  })
}

ed25519.publicKeyFromPrivateKey = function (options) {
  options = options || {}
  const privateKey = messageToNativeBuffer({
    message: options.privateKey,
    encoding: 'binary',
  })
  if (privateKey.length !== ed25519.constants.PRIVATE_KEY_BYTE_LENGTH) {
    throw new TypeError(
      `"options.privateKey" must have a byte length of ${
        ed25519.constants.PRIVATE_KEY_BYTE_LENGTH}`,
    )
  }

  const pk = new NativeBuffer(ed25519.constants.PUBLIC_KEY_BYTE_LENGTH)
  for (let i = 0; i < pk.length; ++i) {
    pk[i] = privateKey[32 + i]
  }
  return pk
}

ed25519.sign = function (options) {
  options = options || {}
  const msg = messageToNativeBuffer(options)
  let privateKey = messageToNativeBuffer({
    message: options.privateKey,
    encoding: 'binary',
  })
  if (privateKey.length === ed25519.constants.SEED_BYTE_LENGTH) {
    const keyPair = ed25519.generateKeyPair({ seed: privateKey })
    privateKey = keyPair.privateKey
  }
  else if (privateKey.length !== ed25519.constants.PRIVATE_KEY_BYTE_LENGTH) {
    throw new TypeError(
      `"options.privateKey" must have a byte length of ${
        ed25519.constants.SEED_BYTE_LENGTH} or ${
        ed25519.constants.PRIVATE_KEY_BYTE_LENGTH}`,
    )
  }

  const signedMsg = new NativeBuffer(
    ed25519.constants.SIGN_BYTE_LENGTH + msg.length,
  )
  crypto_sign(signedMsg, msg, msg.length, privateKey)

  const sig = new NativeBuffer(ed25519.constants.SIGN_BYTE_LENGTH)
  for (let i = 0; i < sig.length; ++i) {
    sig[i] = signedMsg[i]
  }
  return sig
}

ed25519.verify = function (options) {
  options = options || {}
  const msg = messageToNativeBuffer(options)
  if (options.signature === undefined) {
    throw new TypeError(
      '"options.signature" must be a node.js Buffer, a Uint8Array, a forge '
      + 'ByteBuffer, or a binary string.',
    )
  }
  const sig = messageToNativeBuffer({
    message: options.signature,
    encoding: 'binary',
  })
  if (sig.length !== ed25519.constants.SIGN_BYTE_LENGTH) {
    throw new TypeError(
      `"options.signature" must have a byte length of ${
        ed25519.constants.SIGN_BYTE_LENGTH}`,
    )
  }

  const publicKey = messageToNativeBuffer({
    message: options.publicKey,
    encoding: 'binary',
  })

  if (publicKey.length !== ed25519.constants.PUBLIC_KEY_BYTE_LENGTH) {
    throw new TypeError(
      `"options.publicKey" must have a byte length of ${
        ed25519.constants.PUBLIC_KEY_BYTE_LENGTH}`,
    )
  }

  const sm = new NativeBuffer(ed25519.constants.SIGN_BYTE_LENGTH + msg.length)
  const m = new NativeBuffer(ed25519.constants.SIGN_BYTE_LENGTH + msg.length)

  let i
  for (i = 0; i < ed25519.constants.SIGN_BYTE_LENGTH; ++i) {
    sm[i] = sig[i]
  }
  for (i = 0; i < msg.length; ++i) {
    sm[i + ed25519.constants.SIGN_BYTE_LENGTH] = msg[i]
  }
  return (crypto_sign_open(m, sm, sm.length, publicKey) >= 0)
}

function messageToNativeBuffer(options: Ed25519Options): Buffer | Uint8Array {
  let message = options.message
  if (message instanceof Uint8Array || message instanceof NativeBuffer) {
    return message
  }

  let encoding = options.encoding
  if (message === undefined) {
    if (options.md) {
      message = options.md.digest().getBytes()
      encoding = 'binary'
    }
    else {
      throw new TypeError('"options.message" or "options.md" not specified.')
    }
  }

  if (typeof message === 'string' && !encoding) {
    throw new TypeError('"options.encoding" must be "binary" or "utf8".')
  }

  if (typeof message === 'string') {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(message, encoding as BufferEncoding)
    }
    const buf = new ByteBuffer()
    buf.putString(message)
    message = buf
  }
  else if (!(message instanceof ByteBuffer)) {
    throw new TypeError(
      '"options.message" must be a node.js Buffer, a Uint8Array, a forge '
      + 'ByteBuffer, or a string with "options.encoding" specifying its '
      + 'encoding.',
    )
  }

  // convert to native buffer
  const buffer = new NativeBuffer(message.length())
  for (let i = 0; i < buffer.length; ++i) {
    buffer[i] = message.getByte()
  }
  return buffer
}

const gf0 = gf()
const gf1 = gf([1])
const D = gf([
  0x78A3,
  0x1359,
  0x4DCA,
  0x75EB,
  0xD8AB,
  0x4141,
  0x0A4D,
  0x0070,
  0xE898,
  0x7779,
  0x4079,
  0x8CC7,
  0xFE73,
  0x2B6F,
  0x6CEE,
  0x5203,
])
const D2 = gf([
  0xF159,
  0x26B2,
  0x9B94,
  0xEBD6,
  0xB156,
  0x8283,
  0x149A,
  0x00E0,
  0xD130,
  0xEEF3,
  0x80F2,
  0x198E,
  0xFCE7,
  0x56DF,
  0xD9DC,
  0x2406,
])
const X = gf([
  0xD51A,
  0x8F25,
  0x2D60,
  0xC956,
  0xA7B2,
  0x9525,
  0xC760,
  0x692C,
  0xDC5C,
  0xFDD6,
  0xE231,
  0xC0A4,
  0x53FE,
  0xCD6E,
  0x36D3,
  0x2169,
])
const Y = gf([
  0x6658,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
])
const L = new Float64Array([
  0xED,
  0xD3,
  0xF5,
  0x5C,
  0x1A,
  0x63,
  0x12,
  0x58,
  0xD6,
  0x9C,
  0xF7,
  0xA2,
  0xDE,
  0xF9,
  0xDE,
  0x14,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0x10,
])
const I = gf([
  0xA0B0,
  0x4A0E,
  0x1B27,
  0xC4EE,
  0xE478,
  0xAD2F,
  0x1806,
  0x2F43,
  0xD7A7,
  0x3DFB,
  0x0099,
  0x2B4D,
  0xDF0B,
  0x4FC1,
  0x2480,
  0x2B83,
])

function sha512(msg: Buffer | Uint8Array, msgLen: number): Buffer | Uint8Array {
  const md = sha.create()
  const buffer = new ByteBuffer()
  const msgStr = Buffer.from(msg).toString('binary')
  buffer.putString(msgStr)
  md.update(buffer.toString(), 'binary')
  const hash = md.digest().getBytes()
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(hash, 'binary')
  }
  const out = new NativeBuffer(ed25519.constants.HASH_BYTE_LENGTH)
  for (let i = 0; i < 64; ++i) {
    out[i] = hash.charCodeAt(i)
  }
  return out
}

function crypto_sign_keypair(
  pk: Buffer | Uint8Array,
  sk: Buffer | Uint8Array,
): number {
  const p = [gf(), gf(), gf(), gf()]
  let i

  const d = sha512(sk, 32)
  d[0] &= 248
  d[31] &= 127
  d[31] |= 64

  scalarbase(p, d)
  pack(pk, p)

  for (i = 0; i < 32; ++i) {
    sk[i + 32] = pk[i]
  }
  return 0
}

// Note: difference from C - smlen returned, not passed as argument.
function crypto_sign(
  sm: Buffer | Uint8Array,
  m: Buffer | Uint8Array,
  n: number,
  sk: Buffer | Uint8Array,
): number {
  let i; let j; const x = new Float64Array(64)
  const p = [gf(), gf(), gf(), gf()]

  const d = sha512(sk, 32)
  d[0] &= 248
  d[31] &= 127
  d[31] |= 64

  const smlen = n + 64
  for (i = 0; i < n; ++i) {
    sm[64 + i] = m[i]
  }
  for (i = 0; i < 32; ++i) {
    sm[32 + i] = d[32 + i]
  }

  const r = sha512(sm.subarray(32), n + 32)
  reduce(r)
  scalarbase(p, r)
  pack(sm, p)

  for (i = 32; i < 64; ++i) {
    sm[i] = sk[i]
  }
  const h = sha512(sm, n + 64)
  reduce(h)

  for (i = 32; i < 64; ++i) {
    x[i] = 0
  }
  for (i = 0; i < 32; ++i) {
    x[i] = r[i]
  }
  for (i = 0; i < 32; ++i) {
    for (j = 0; j < 32; j++) {
      x[i + j] += h[i] * d[j]
    }
  }

  modL(sm.subarray(32), x)
  return smlen
}

function crypto_sign_open(
  m: Buffer | Uint8Array,
  sm: Buffer | Uint8Array,
  n: number,
  pk: Buffer | Uint8Array,
): number {
  let i, mlen
  const t = new NativeBuffer(32)
  const p = [gf(), gf(), gf(), gf()]
  const q = [gf(), gf(), gf(), gf()]

  mlen = -1
  if (n < 64) {
    return -1
  }

  if (unpackneg(q, pk)) {
    return -1
  }

  for (i = 0; i < n; ++i) {
    m[i] = sm[i]
  }

  for (i = 0; i < 32; ++i) {
    m[i + 32] = pk[i]
  }

  const h = sha512(m, n)
  reduce(h)
  scalarmult(p, q, Array.from(h))

  scalarbase(q, sm.subarray(32))
  add(p, q)
  pack(t, p)

  n -= 64

  if (crypto_verify_32(sm, 0, t, 0)) {
    for (i = 0; i < n; ++i) {
      m[i] = 0
    }

    return -1
  }

  for (i = 0; i < n; ++i) {
    m[i] = sm[i + 64]
  }

  mlen = n

  return mlen
}

function modL(r: number[], x: number[]) {
  let carry, i, j, k

  for (i = 63; i >= 32; --i) {
    carry = 0

    for (j = i - 32, k = i - 12; j < k; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)]
      carry = (x[j] + 128) >> 8
      x[j] -= carry * 256
    }

    x[j] += carry
    x[i] = 0
  }

  carry = 0

  for (j = 0; j < 32; ++j) {
    x[j] += carry - (x[31] >> 4) * L[j]
    carry = x[j] >> 8
    x[j] &= 255
  }

  for (j = 0; j < 32; ++j) {
    x[j] -= carry * L[j]
  }

  for (i = 0; i < 32; ++i) {
    x[i + 1] += x[i] >> 8
    r[i] = x[i] & 255
  }
}

function reduce(r: Buffer | Uint8Array) {
  const x = new Float64Array(64)

  for (let i = 0; i < 64; ++i) {
    x[i] = r[i]
    r[i] = 0
  }

  modL(r, x)
}

function add(p: number[], q: number[]) {
  const a = gf(); const b = gf(); const c = gf()
  const d = gf(); const e = gf(); const f = gf()
  const g = gf(); const h = gf(); const t = gf()

  Z(a, p[1], p[0])
  Z(t, q[1], q[0])
  M(a, a, t)
  A(b, p[0], p[1])
  A(t, q[0], q[1])
  M(b, b, t)
  M(c, p[3], q[3])
  M(c, c, D2)
  M(d, p[2], q[2])
  A(d, d, d)
  Z(e, b, a)
  Z(f, d, c)
  A(g, d, c)
  A(h, b, a)

  M(p[0], e, f)
  M(p[1], h, g)
  M(p[2], g, f)
  M(p[3], e, h)
}

function cswap(p: number[], q: number[], b: number) {
  for (let i = 0; i < 4; ++i) {
    sel25519(p[i], q[i], b)
  }
}

function pack(r: number[], p: number[]) {
  const tx = gf(); const ty = gf(); const zi = gf()
  inv25519(zi, p[2])
  M(tx, p[0], zi)
  M(ty, p[1], zi)
  pack25519(r, ty)
  r[31] ^= par25519(tx) << 7
}

function pack25519(o: number[], n: number[]) {
  let i, j, b
  const m = gf(); const t = gf()
  for (i = 0; i < 16; ++i) {
    t[i] = n[i]
  }
  car25519(t)
  car25519(t)
  car25519(t)
  for (j = 0; j < 2; ++j) {
    m[0] = t[0] - 0xFFED
    for (i = 1; i < 15; ++i) {
      m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1)
      m[i - 1] &= 0xFFFF
    }
    m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1)
    b = (m[15] >> 16) & 1
    m[14] &= 0xFFFF
    sel25519(t, m, 1 - b)
  }
  for (i = 0; i < 16; i++) {
    o[2 * i] = t[i] & 0xFF
    o[2 * i + 1] = t[i] >> 8
  }
}

function unpackneg(r: number[], p: number[]) {
  const t = gf(); const chk = gf(); const num = gf()
  const den = gf(); const den2 = gf(); const den4 = gf()
  const den6 = gf()

  set25519(r[2], gf1)
  unpack25519(r[1], p)
  S(num, r[1])
  M(den, num, D)
  Z(num, num, r[2])
  A(den, r[2], den)

  S(den2, den)
  S(den4, den2)
  M(den6, den4, den2)
  M(t, den6, num)
  M(t, t, den)

  pow2523(t, t)
  M(t, t, num)
  M(t, t, den)
  M(t, t, den)
  M(r[0], t, den)

  S(chk, r[0])
  M(chk, chk, den)

  if (neq25519(chk, num)) {
    M(r[0], r[0], I)
  }

  S(chk, r[0])
  M(chk, chk, den)

  if (neq25519(chk, num)) {
    return -1
  }

  if (par25519(r[0]) === (p[31] >> 7))
    Z(r[0], gf0, r[0])

  M(r[3], r[0], r[1])

  return 0
}

function unpack25519(o: number[], n: number[]) {
  let i

  for (i = 0; i < 16; ++i) {
    o[i] = n[2 * i] + (n[2 * i + 1] << 8)
  }

  o[15] &= 0x7FFF
}

function pow2523(o: number[], i: number[]) {
  const c = gf()

  let a
  for (a = 0; a < 16; ++a) {
    c[a] = i[a]
  }

  for (a = 250; a >= 0; --a) {
    S(c, c)

    if (a !== 1) {
      M(c, c, i)
    }
  }

  for (a = 0; a < 16; ++a) {
    o[a] = c[a]
  }
}

function neq25519(a: number[], b: number[]) {
  const c = new NativeBuffer(32)
  const d = new NativeBuffer(32)

  pack25519(c, a)
  pack25519(d, b)

  return crypto_verify_32(c, 0, d, 0)
}

function crypto_verify_32(x: number[], xi: number, y: number[], yi: number) {
  return vn(x, xi, y, yi, 32)
}

function vn(x: number[], xi: number, y: number[], yi: number, n: number) {
  let i; let d = 0

  for (i = 0; i < n; ++i)
    d |= x[xi + i] ^ y[yi + i]

  return (1 & ((d - 1) >>> 8)) - 1
}

function par25519(a: number[]) {
  const d = new NativeBuffer(32)
  pack25519(d, a)
  return d[0] & 1
}

function scalarmult(p: number[], q: number[], s: number[]) {
  let b, i

  set25519(p[0], gf0)
  set25519(p[1], gf1)
  set25519(p[2], gf1)
  set25519(p[3], gf0)

  for (i = 255; i >= 0; --i) {
    b = (s[(i / 8) | 0] >> (i & 7)) & 1
    cswap(p, q, b)
    add(q, p)
    add(p, p)
    cswap(p, q, b)
  }
}

function scalarbase(p: number[], s: number[]) {
  const q = [gf(), gf(), gf(), gf()]

  set25519(q[0], X)
  set25519(q[1], Y)
  set25519(q[2], gf1)
  M(q[3], X, Y)
  scalarmult(p, q, s)
}

function set25519(r: number[], a: number[]) {
  let i
  for (i = 0; i < 16; i++) {
    r[i] = a[i] | 0
  }
}

function inv25519(o: number[], i: number[]) {
  const c = gf()
  let a
  for (a = 0; a < 16; ++a) {
    c[a] = i[a]
  }

  for (a = 253; a >= 0; --a) {
    S(c, c)
    if (a !== 2 && a !== 4) {
      M(c, c, i)
    }
  }

  for (a = 0; a < 16; ++a) {
    o[a] = c[a]
  }
}

function car25519(o: number[]) {
  let i
  let v
  let c = 1

  for (i = 0; i < 16; ++i) {
    v = o[i] + c + 65535
    c = Math.floor(v / 65536)
    o[i] = v - c * 65536
  }

  o[0] += c - 1 + 37 * (c - 1)
}

function sel25519(p: number[], q: number[], b: number) {
  let t
  const c = ~(b - 1)

  for (let i = 0; i < 16; ++i) {
    t = c & (p[i] ^ q[i])
    p[i] ^= t
    q[i] ^= t
  }
}

function A(o: number[], a: number[], b: number[]) {
  for (let i = 0; i < 16; ++i)
    o[i] = a[i] + b[i]
}

function Z(o: number[], a: number[], b: number[]) {
  for (let i = 0; i < 16; ++i)
    o[i] = a[i] - b[i]
}

function S(o: number[], a: number[]) {
  M(o, a, a)
}

function M(o: number[], a: number[], b: number[]) {
  let v; let c
  let t0 = 0; let t1 = 0; let t2 = 0; let t3 = 0; let t4 = 0; let t5 = 0; let t6 = 0; let t7 = 0
  let t8 = 0; let t9 = 0; let t10 = 0; let t11 = 0; let t12 = 0; let t13 = 0; let t14 = 0; let t15 = 0
  let t16 = 0; let t17 = 0; let t18 = 0; let t19 = 0; let t20 = 0; let t21 = 0; let t22 = 0; let t23 = 0
  let t24 = 0; let t25 = 0; let t26 = 0; let t27 = 0; let t28 = 0; let t29 = 0; let t30 = 0
  const b0 = b[0]
  const b1 = b[1]
  const b2 = b[2]
  const b3 = b[3]
  const b4 = b[4]
  const b5 = b[5]
  const b6 = b[6]
  const b7 = b[7]
  const b8 = b[8]
  const b9 = b[9]
  const b10 = b[10]
  const b11 = b[11]
  const b12 = b[12]
  const b13 = b[13]
  const b14 = b[14]
  const b15 = b[15]

  v = a[0]
  t0 += v * b0
  t1 += v * b1
  t2 += v * b2
  t3 += v * b3
  t4 += v * b4
  t5 += v * b5
  t6 += v * b6
  t7 += v * b7
  t8 += v * b8
  t9 += v * b9
  t10 += v * b10
  t11 += v * b11
  t12 += v * b12
  t13 += v * b13
  t14 += v * b14
  t15 += v * b15
  v = a[1]
  t1 += v * b0
  t2 += v * b1
  t3 += v * b2
  t4 += v * b3
  t5 += v * b4
  t6 += v * b5
  t7 += v * b6
  t8 += v * b7
  t9 += v * b8
  t10 += v * b9
  t11 += v * b10
  t12 += v * b11
  t13 += v * b12
  t14 += v * b13
  t15 += v * b14
  t16 += v * b15
  v = a[2]
  t2 += v * b0
  t3 += v * b1
  t4 += v * b2
  t5 += v * b3
  t6 += v * b4
  t7 += v * b5
  t8 += v * b6
  t9 += v * b7
  t10 += v * b8
  t11 += v * b9
  t12 += v * b10
  t13 += v * b11
  t14 += v * b12
  t15 += v * b13
  t16 += v * b14
  t17 += v * b15
  v = a[3]
  t3 += v * b0
  t4 += v * b1
  t5 += v * b2
  t6 += v * b3
  t7 += v * b4
  t8 += v * b5
  t9 += v * b6
  t10 += v * b7
  t11 += v * b8
  t12 += v * b9
  t13 += v * b10
  t14 += v * b11
  t15 += v * b12
  t16 += v * b13
  t17 += v * b14
  t18 += v * b15
  v = a[4]
  t4 += v * b0
  t5 += v * b1
  t6 += v * b2
  t7 += v * b3
  t8 += v * b4
  t9 += v * b5
  t10 += v * b6
  t11 += v * b7
  t12 += v * b8
  t13 += v * b9
  t14 += v * b10
  t15 += v * b11
  t16 += v * b12
  t17 += v * b13
  t18 += v * b14
  t19 += v * b15
  v = a[5]
  t5 += v * b0
  t6 += v * b1
  t7 += v * b2
  t8 += v * b3
  t9 += v * b4
  t10 += v * b5
  t11 += v * b6
  t12 += v * b7
  t13 += v * b8
  t14 += v * b9
  t15 += v * b10
  t16 += v * b11
  t17 += v * b12
  t18 += v * b13
  t19 += v * b14
  t20 += v * b15
  v = a[6]
  t6 += v * b0
  t7 += v * b1
  t8 += v * b2
  t9 += v * b3
  t10 += v * b4
  t11 += v * b5
  t12 += v * b6
  t13 += v * b7
  t14 += v * b8
  t15 += v * b9
  t16 += v * b10
  t17 += v * b11
  t18 += v * b12
  t19 += v * b13
  t20 += v * b14
  t21 += v * b15
  v = a[7]
  t7 += v * b0
  t8 += v * b1
  t9 += v * b2
  t10 += v * b3
  t11 += v * b4
  t12 += v * b5
  t13 += v * b6
  t14 += v * b7
  t15 += v * b8
  t16 += v * b9
  t17 += v * b10
  t18 += v * b11
  t19 += v * b12
  t20 += v * b13
  t21 += v * b14
  t22 += v * b15
  v = a[8]
  t8 += v * b0
  t9 += v * b1
  t10 += v * b2
  t11 += v * b3
  t12 += v * b4
  t13 += v * b5
  t14 += v * b6
  t15 += v * b7
  t16 += v * b8
  t17 += v * b9
  t18 += v * b10
  t19 += v * b11
  t20 += v * b12
  t21 += v * b13
  t22 += v * b14
  t23 += v * b15
  v = a[9]
  t9 += v * b0
  t10 += v * b1
  t11 += v * b2
  t12 += v * b3
  t13 += v * b4
  t14 += v * b5
  t15 += v * b6
  t16 += v * b7
  t17 += v * b8
  t18 += v * b9
  t19 += v * b10
  t20 += v * b11
  t21 += v * b12
  t22 += v * b13
  t24 += v * b14
  t25 += v * b15
  v = a[10]
  t10 += v * b0
  t11 += v * b1
  t12 += v * b2
  t13 += v * b3
  t14 += v * b4
  t15 += v * b5
  t16 += v * b6
  t17 += v * b7
  t18 += v * b8
  t19 += v * b9
  t20 += v * b10
  t21 += v * b11
  t22 += v * b12
  t23 += v * b13
  t24 += v * b14
  t25 += v * b15
  v = a[11]
  t11 += v * b0
  t12 += v * b1
  t13 += v * b2
  t14 += v * b3
  t15 += v * b4
  t16 += v * b5
  t17 += v * b6
  t18 += v * b7
  t19 += v * b8
  t20 += v * b9
  t21 += v * b10
  t22 += v * b11
  t23 += v * b12
  t24 += v * b13
  t26 += v * b14
  t27 += v * b15
  v = a[12]
  t12 += v * b0
  t13 += v * b1
  t14 += v * b2
  t15 += v * b3
  t16 += v * b4
  t17 += v * b5
  t18 += v * b6
  t19 += v * b7
  t20 += v * b8
  t21 += v * b9
  t22 += v * b10
  t23 += v * b11
  t24 += v * b12
  t25 += v * b13
  t26 += v * b14
  t27 += v * b15
  v = a[13]
  t13 += v * b0
  t14 += v * b1
  t15 += v * b2
  t16 += v * b3
  t17 += v * b4
  t18 += v * b5
  t19 += v * b6
  t20 += v * b7
  t21 += v * b8
  t22 += v * b9
  t23 += v * b10
  t24 += v * b11
  t25 += v * b12
  t26 += v * b13
  t27 += v * b14
  t28 += v * b15
  v = a[14]
  t14 += v * b0
  t15 += v * b1
  t16 += v * b2
  t17 += v * b3
  t18 += v * b4
  t19 += v * b5
  t20 += v * b6
  t21 += v * b7
  t22 += v * b8
  t23 += v * b9
  t24 += v * b10
  t25 += v * b11
  t26 += v * b12
  t27 += v * b13
  t28 += v * b14
  t29 += v * b15
  v = a[15]
  t15 += v * b0
  t16 += v * b1
  t17 += v * b2
  t18 += v * b3
  t19 += v * b4
  t20 += v * b5
  t21 += v * b6
  t22 += v * b7
  t23 += v * b8
  t24 += v * b9
  t25 += v * b10
  t26 += v * b11
  t27 += v * b12
  t28 += v * b13
  t29 += v * b14
  t30 += v * b15

  t0 += 38 * t16
  t1 += 38 * t17
  t2 += 38 * t18
  t3 += 38 * t19
  t4 += 38 * t20
  t5 += 38 * t21
  t6 += 38 * t22
  t7 += 38 * t23
  t8 += 38 * t24
  t9 += 38 * t25
  t10 += 38 * t26
  t11 += 38 * t27
  t12 += 38 * t28
  t13 += 38 * t29
  t14 += 38 * t30
  // t15 left as is

  // first car
  c = 1
  v = t0 + c + 65535; c = Math.floor(v / 65536); t0 = v - c * 65536
  v = t1 + c + 65535; c = Math.floor(v / 65536); t1 = v - c * 65536
  v = t2 + c + 65535; c = Math.floor(v / 65536); t2 = v - c * 65536
  v = t3 + c + 65535; c = Math.floor(v / 65536); t3 = v - c * 65536
  v = t4 + c + 65535; c = Math.floor(v / 65536); t4 = v - c * 65536
  v = t5 + c + 65535; c = Math.floor(v / 65536); t5 = v - c * 65536
  v = t6 + c + 65535; c = Math.floor(v / 65536); t6 = v - c * 65536
  v = t7 + c + 65535; c = Math.floor(v / 65536); t7 = v - c * 65536
  v = t8 + c + 65535; c = Math.floor(v / 65536); t8 = v - c * 65536
  v = t9 + c + 65535; c = Math.floor(v / 65536); t9 = v - c * 65536
  v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536
  v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536
  v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536
  v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536
  v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536
  v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536
  t0 += c - 1 + 37 * (c - 1)

  // second car
  c = 1
  v = t0 + c + 65535; c = Math.floor(v / 65536); t0 = v - c * 65536
  v = t1 + c + 65535; c = Math.floor(v / 65536); t1 = v - c * 65536
  v = t2 + c + 65535; c = Math.floor(v / 65536); t2 = v - c * 65536
  v = t3 + c + 65535; c = Math.floor(v / 65536); t3 = v - c * 65536
  v = t4 + c + 65535; c = Math.floor(v / 65536); t4 = v - c * 65536
  v = t5 + c + 65535; c = Math.floor(v / 65536); t5 = v - c * 65536
  v = t6 + c + 65535; c = Math.floor(v / 65536); t6 = v - c * 65536
  v = t7 + c + 65535; c = Math.floor(v / 65536); t7 = v - c * 65536
  v = t8 + c + 65535; c = Math.floor(v / 65536); t8 = v - c * 65536
  v = t9 + c + 65535; c = Math.floor(v / 65536); t9 = v - c * 65536
  v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536
  v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536
  v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536
  v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536
  v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536
  v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536
  t0 += c - 1 + 37 * (c - 1)

  o[0] = t0
  o[1] = t1
  o[2] = t2
  o[3] = t3
  o[4] = t4
  o[5] = t5
  o[6] = t6
  o[7] = t7
  o[8] = t8
  o[9] = t9
  o[10] = t10
  o[11] = t11
  o[12] = t12
  o[13] = t13
  o[14] = t14
  o[15] = t15
}
