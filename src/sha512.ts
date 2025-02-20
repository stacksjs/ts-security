/**
 * Secure Hash Algorithm with a 1024-bit block size implementation.
 *
 * This includes: SHA-512, SHA-384, SHA-512/224, and SHA-512/256. For
 * SHA-256 (block size 512 bits), see sha256.js.
 *
 * See FIPS 180-4 for details.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2014-2015 Digital Bazaar, Inc.
 */
const forge = require('./forge')
require('./md')
require('./util')

const sha512 = module.exports = forge.sha512 = forge.sha512 || {}

// SHA-512
forge.md.sha512 = forge.md.algorithms.sha512 = sha512

// SHA-384
const sha384 = forge.sha384 = forge.sha512.sha384 = forge.sha512.sha384 || {}
sha384.create = function () {
  return sha512.create('SHA-384')
}
forge.md.sha384 = forge.md.algorithms.sha384 = sha384

// SHA-512/256
forge.sha512.sha256 = forge.sha512.sha256 || {
  create() {
    return sha512.create('SHA-512/256')
  },
}
forge.md['sha512/256'] = forge.md.algorithms['sha512/256']
  = forge.sha512.sha256

// SHA-512/224
forge.sha512.sha224 = forge.sha512.sha224 || {
  create() {
    return sha512.create('SHA-512/224')
  },
}
forge.md['sha512/224'] = forge.md.algorithms['sha512/224']
  = forge.sha512.sha224

/**
 * Creates a SHA-2 message digest object.
 *
 * @param algorithm the algorithm to use (SHA-512, SHA-384, SHA-512/224,
 *          SHA-512/256).
 *
 * @return a message digest object.
 */
sha512.create = function (algorithm) {
  // do initialization as necessary
  if (!_initialized) {
    _init()
  }

  if (typeof algorithm === 'undefined') {
    algorithm = 'SHA-512'
  }

  if (!(algorithm in _states)) {
    throw new Error(`Invalid SHA-512 algorithm: ${algorithm}`)
  }

  // SHA-512 state contains eight 64-bit integers (each as two 32-bit ints)
  const _state = _states[algorithm]
  let _h = null

  // input buffer
  let _input = forge.util.createBuffer()

  // used for 64-bit word storage
  const _w = Array.from({ length: 80 })
  for (let wi = 0; wi < 80; ++wi) {
    _w[wi] = Array.from({ length: 2 })
  }

  // determine digest length by algorithm name (default)
  let digestLength = 64
  switch (algorithm) {
    case 'SHA-384':
      digestLength = 48
      break
    case 'SHA-512/256':
      digestLength = 32
      break
    case 'SHA-512/224':
      digestLength = 28
      break
  }

  // message digest object
  const md = {
    // SHA-512 => sha512
    algorithm: algorithm.replace('-', '').toLowerCase(),
    blockLength: 128,
    digestLength,
    // 56-bit length of message so far (does not including padding)
    messageLength: 0,
    // true message length
    fullMessageLength: null,
    // size of message length in bytes
    messageLengthSize: 16,
  }

  /**
   * Starts the digest.
   *
   * @return this digest object.
   */
  md.start = function () {
    // up to 56-bit message length for convenience
    md.messageLength = 0

    // full message length (set md.messageLength128 for backwards-compatibility)
    md.fullMessageLength = md.messageLength128 = []
    const int32s = md.messageLengthSize / 4
    for (var i = 0; i < int32s; ++i) {
      md.fullMessageLength.push(0)
    }
    _input = forge.util.createBuffer()
    _h = Array.from({ length: _state.length })
    for (var i = 0; i < _state.length; ++i) {
      _h[i] = _state[i].slice(0)
    }
    return md
  }
  // start digest automatically for first time
  md.start()

  /**
   * Updates the digest with the given message input. The given input can
   * treated as raw input (no encoding will be applied) or an encoding of
   * 'utf8' maybe given to encode the input using UTF-8.
   *
   * @param msg the message input to update with.
   * @param encoding the encoding to use (default: 'raw', other: 'utf8').
   *
   * @return this digest object.
   */
  md.update = function (msg, encoding) {
    if (encoding === 'utf8') {
      msg = forge.util.encodeUtf8(msg)
    }

    // update message length
    let len = msg.length
    md.messageLength += len
    len = [(len / 0x100000000) >>> 0, len >>> 0]
    for (let i = md.fullMessageLength.length - 1; i >= 0; --i) {
      md.fullMessageLength[i] += len[1]
      len[1] = len[0] + ((md.fullMessageLength[i] / 0x100000000) >>> 0)
      md.fullMessageLength[i] = md.fullMessageLength[i] >>> 0
      len[0] = ((len[1] / 0x100000000) >>> 0)
    }

    // add bytes to input buffer
    _input.putBytes(msg)

    // process bytes
    _update(_h, _w, _input)

    // compact input buffer every 2K or if empty
    if (_input.read > 2048 || _input.length() === 0) {
      _input.compact()
    }

    return md
  }

  /**
   * Produces the digest.
   *
   * @return a byte buffer containing the digest value.
   */
  md.digest = function () {
    /* Note: Here we copy the remaining bytes in the input buffer and
    add the appropriate SHA-512 padding. Then we do the final update
    on a copy of the state so that if the user wants to get
    intermediate digests they can do so. */

    /* Determine the number of bytes that must be added to the message
    to ensure its length is congruent to 896 mod 1024. In other words,
    the data to be digested must be a multiple of 1024 bits (or 128 bytes).
    This data includes the message, some padding, and the length of the
    message. Since the length of the message will be encoded as 16 bytes (128
    bits), that means that the last segment of the data must have 112 bytes
    (896 bits) of message and padding. Therefore, the length of the message
    plus the padding must be congruent to 896 mod 1024 because
    1024 - 128 = 896.

    In order to fill up the message length it must be filled with
    padding that begins with 1 bit followed by all 0 bits. Padding
    must *always* be present, so if the message length is already
    congruent to 896 mod 1024, then 1024 padding bits must be added. */

    const finalBlock = forge.util.createBuffer()
    finalBlock.putBytes(_input.bytes())

    // compute remaining size to be digested (include message length size)
    const remaining = (
      md.fullMessageLength[md.fullMessageLength.length - 1]
      + md.messageLengthSize)

    // add padding for overflow blockSize - overflow
    // _padding starts with 1 byte with first bit is set (byte value 128), then
    // there may be up to (blockSize - 1) other pad bytes
    const overflow = remaining & (md.blockLength - 1)
    finalBlock.putBytes(_padding.substr(0, md.blockLength - overflow))

    // serialize message length in bits in big-endian order; since length
    // is stored in bytes we multiply by 8 and add carry from next int
    let next, carry
    let bits = md.fullMessageLength[0] * 8
    for (var i = 0; i < md.fullMessageLength.length - 1; ++i) {
      next = md.fullMessageLength[i + 1] * 8
      carry = (next / 0x100000000) >>> 0
      bits += carry
      finalBlock.putInt32(bits >>> 0)
      bits = next >>> 0
    }
    finalBlock.putInt32(bits)

    const h = Array.from({ length: _h.length })
    for (var i = 0; i < _h.length; ++i) {
      h[i] = _h[i].slice(0)
    }
    _update(h, _w, finalBlock)
    const rval = forge.util.createBuffer()
    let hlen
    if (algorithm === 'SHA-512') {
      hlen = h.length
    }
    else if (algorithm === 'SHA-384') {
      hlen = h.length - 2
    }
    else {
      hlen = h.length - 4
    }
    for (var i = 0; i < hlen; ++i) {
      rval.putInt32(h[i][0])
      if (i !== hlen - 1 || algorithm !== 'SHA-512/224') {
        rval.putInt32(h[i][1])
      }
    }
    return rval
  }

  return md
}

// sha-512 padding bytes not initialized yet
var _padding = null
var _initialized = false

// table of constants
let _k = null

// initial hash states
var _states = null

/**
 * Initializes the constant tables.
 */
function _init() {
  // create padding
  _padding = String.fromCharCode(128)
  _padding += forge.util.fillString(String.fromCharCode(0x00), 128)

  // create K table for SHA-512
  _k = [
    [0x428A2F98, 0xD728AE22],
    [0x71374491, 0x23EF65CD],
    [0xB5C0FBCF, 0xEC4D3B2F],
    [0xE9B5DBA5, 0x8189DBBC],
    [0x3956C25B, 0xF348B538],
    [0x59F111F1, 0xB605D019],
    [0x923F82A4, 0xAF194F9B],
    [0xAB1C5ED5, 0xDA6D8118],
    [0xD807AA98, 0xA3030242],
    [0x12835B01, 0x45706FBE],
    [0x243185BE, 0x4EE4B28C],
    [0x550C7DC3, 0xD5FFB4E2],
    [0x72BE5D74, 0xF27B896F],
    [0x80DEB1FE, 0x3B1696B1],
    [0x9BDC06A7, 0x25C71235],
    [0xC19BF174, 0xCF692694],
    [0xE49B69C1, 0x9EF14AD2],
    [0xEFBE4786, 0x384F25E3],
    [0x0FC19DC6, 0x8B8CD5B5],
    [0x240CA1CC, 0x77AC9C65],
    [0x2DE92C6F, 0x592B0275],
    [0x4A7484AA, 0x6EA6E483],
    [0x5CB0A9DC, 0xBD41FBD4],
    [0x76F988DA, 0x831153B5],
    [0x983E5152, 0xEE66DFAB],
    [0xA831C66D, 0x2DB43210],
    [0xB00327C8, 0x98FB213F],
    [0xBF597FC7, 0xBEEF0EE4],
    [0xC6E00BF3, 0x3DA88FC2],
    [0xD5A79147, 0x930AA725],
    [0x06CA6351, 0xE003826F],
    [0x14292967, 0x0A0E6E70],
    [0x27B70A85, 0x46D22FFC],
    [0x2E1B2138, 0x5C26C926],
    [0x4D2C6DFC, 0x5AC42AED],
    [0x53380D13, 0x9D95B3DF],
    [0x650A7354, 0x8BAF63DE],
    [0x766A0ABB, 0x3C77B2A8],
    [0x81C2C92E, 0x47EDAEE6],
    [0x92722C85, 0x1482353B],
    [0xA2BFE8A1, 0x4CF10364],
    [0xA81A664B, 0xBC423001],
    [0xC24B8B70, 0xD0F89791],
    [0xC76C51A3, 0x0654BE30],
    [0xD192E819, 0xD6EF5218],
    [0xD6990624, 0x5565A910],
    [0xF40E3585, 0x5771202A],
    [0x106AA070, 0x32BBD1B8],
    [0x19A4C116, 0xB8D2D0C8],
    [0x1E376C08, 0x5141AB53],
    [0x2748774C, 0xDF8EEB99],
    [0x34B0BCB5, 0xE19B48A8],
    [0x391C0CB3, 0xC5C95A63],
    [0x4ED8AA4A, 0xE3418ACB],
    [0x5B9CCA4F, 0x7763E373],
    [0x682E6FF3, 0xD6B2B8A3],
    [0x748F82EE, 0x5DEFB2FC],
    [0x78A5636F, 0x43172F60],
    [0x84C87814, 0xA1F0AB72],
    [0x8CC70208, 0x1A6439EC],
    [0x90BEFFFA, 0x23631E28],
    [0xA4506CEB, 0xDE82BDE9],
    [0xBEF9A3F7, 0xB2C67915],
    [0xC67178F2, 0xE372532B],
    [0xCA273ECE, 0xEA26619C],
    [0xD186B8C7, 0x21C0C207],
    [0xEADA7DD6, 0xCDE0EB1E],
    [0xF57D4F7F, 0xEE6ED178],
    [0x06F067AA, 0x72176FBA],
    [0x0A637DC5, 0xA2C898A6],
    [0x113F9804, 0xBEF90DAE],
    [0x1B710B35, 0x131C471B],
    [0x28DB77F5, 0x23047D84],
    [0x32CAAB7B, 0x40C72493],
    [0x3C9EBE0A, 0x15C9BEBC],
    [0x431D67C4, 0x9C100D4C],
    [0x4CC5D4BE, 0xCB3E42B6],
    [0x597F299C, 0xFC657E2A],
    [0x5FCB6FAB, 0x3AD6FAEC],
    [0x6C44198C, 0x4A475817],
  ]

  // initial hash states
  _states = {}
  _states['SHA-512'] = [
    [0x6A09E667, 0xF3BCC908],
    [0xBB67AE85, 0x84CAA73B],
    [0x3C6EF372, 0xFE94F82B],
    [0xA54FF53A, 0x5F1D36F1],
    [0x510E527F, 0xADE682D1],
    [0x9B05688C, 0x2B3E6C1F],
    [0x1F83D9AB, 0xFB41BD6B],
    [0x5BE0CD19, 0x137E2179],
  ]
  _states['SHA-384'] = [
    [0xCBBB9D5D, 0xC1059ED8],
    [0x629A292A, 0x367CD507],
    [0x9159015A, 0x3070DD17],
    [0x152FECD8, 0xF70E5939],
    [0x67332667, 0xFFC00B31],
    [0x8EB44A87, 0x68581511],
    [0xDB0C2E0D, 0x64F98FA7],
    [0x47B5481D, 0xBEFA4FA4],
  ]
  _states['SHA-512/256'] = [
    [0x22312194, 0xFC2BF72C],
    [0x9F555FA3, 0xC84C64C2],
    [0x2393B86B, 0x6F53B151],
    [0x96387719, 0x5940EABD],
    [0x96283EE2, 0xA88EFFE3],
    [0xBE5E1E25, 0x53863992],
    [0x2B0199FC, 0x2C85B8AA],
    [0x0EB72DDC, 0x81C52CA2],
  ]
  _states['SHA-512/224'] = [
    [0x8C3D37C8, 0x19544DA2],
    [0x73E19966, 0x89DCD4D6],
    [0x1DFAB7AE, 0x32FF9C82],
    [0x679DD514, 0x582F9FCF],
    [0x0F6D2B69, 0x7BD44DA8],
    [0x77E36F73, 0x04C48942],
    [0x3F9D85A8, 0x6A1D36C8],
    [0x1112E6AD, 0x91D692A1],
  ]

  // now initialized
  _initialized = true
}

/**
 * Updates a SHA-512 state with the given byte buffer.
 *
 * @param s the SHA-512 state to update.
 * @param w the array to use to store words.
 * @param bytes the byte buffer to update with.
 */
function _update(s, w, bytes) {
  // consume 512 bit (128 byte) chunks
  let t1_hi, t1_lo
  let t2_hi, t2_lo
  let s0_hi, s0_lo
  let s1_hi, s1_lo
  let ch_hi, ch_lo
  let maj_hi, maj_lo
  let a_hi, a_lo
  let b_hi, b_lo
  let c_hi, c_lo
  let d_hi, d_lo
  let e_hi, e_lo
  let f_hi, f_lo
  let g_hi, g_lo
  let h_hi, h_lo
  let i, hi, lo, w2, w7, w15, w16
  let len = bytes.length()
  while (len >= 128) {
    // the w array will be populated with sixteen 64-bit big-endian words
    // and then extended into 64 64-bit words according to SHA-512
    for (i = 0; i < 16; ++i) {
      w[i][0] = bytes.getInt32() >>> 0
      w[i][1] = bytes.getInt32() >>> 0
    }
    for (; i < 80; ++i) {
      // for word 2 words ago: ROTR 19(x) ^ ROTR 61(x) ^ SHR 6(x)
      w2 = w[i - 2]
      hi = w2[0]
      lo = w2[1]

      // high bits
      t1_hi = (
        ((hi >>> 19) | (lo << 13)) // ROTR 19
        ^ ((lo >>> 29) | (hi << 3)) // ROTR 61/(swap + ROTR 29)
        ^ (hi >>> 6)) >>> 0 // SHR 6
      // low bits
      t1_lo = (
        ((hi << 13) | (lo >>> 19)) // ROTR 19
        ^ ((lo << 3) | (hi >>> 29)) // ROTR 61/(swap + ROTR 29)
        ^ ((hi << 26) | (lo >>> 6))) >>> 0 // SHR 6

      // for word 15 words ago: ROTR 1(x) ^ ROTR 8(x) ^ SHR 7(x)
      w15 = w[i - 15]
      hi = w15[0]
      lo = w15[1]

      // high bits
      t2_hi = (
        ((hi >>> 1) | (lo << 31)) // ROTR 1
        ^ ((hi >>> 8) | (lo << 24)) // ROTR 8
        ^ (hi >>> 7)) >>> 0 // SHR 7
      // low bits
      t2_lo = (
        ((hi << 31) | (lo >>> 1)) // ROTR 1
        ^ ((hi << 24) | (lo >>> 8)) // ROTR 8
        ^ ((hi << 25) | (lo >>> 7))) >>> 0 // SHR 7

      // sum(t1, word 7 ago, t2, word 16 ago) modulo 2^64 (carry lo overflow)
      w7 = w[i - 7]
      w16 = w[i - 16]
      lo = (t1_lo + w7[1] + t2_lo + w16[1])
      w[i][0] = (t1_hi + w7[0] + t2_hi + w16[0]
        + ((lo / 0x100000000) >>> 0)) >>> 0
      w[i][1] = lo >>> 0
    }

    // initialize hash value for this chunk
    a_hi = s[0][0]
    a_lo = s[0][1]
    b_hi = s[1][0]
    b_lo = s[1][1]
    c_hi = s[2][0]
    c_lo = s[2][1]
    d_hi = s[3][0]
    d_lo = s[3][1]
    e_hi = s[4][0]
    e_lo = s[4][1]
    f_hi = s[5][0]
    f_lo = s[5][1]
    g_hi = s[6][0]
    g_lo = s[6][1]
    h_hi = s[7][0]
    h_lo = s[7][1]

    // round function
    for (i = 0; i < 80; ++i) {
      // Sum1(e) = ROTR 14(e) ^ ROTR 18(e) ^ ROTR 41(e)
      s1_hi = (
        ((e_hi >>> 14) | (e_lo << 18)) // ROTR 14
        ^ ((e_hi >>> 18) | (e_lo << 14)) // ROTR 18
        ^ ((e_lo >>> 9) | (e_hi << 23))) >>> 0 // ROTR 41/(swap + ROTR 9)
      s1_lo = (
        ((e_hi << 18) | (e_lo >>> 14)) // ROTR 14
        ^ ((e_hi << 14) | (e_lo >>> 18)) // ROTR 18
        ^ ((e_lo << 23) | (e_hi >>> 9))) >>> 0 // ROTR 41/(swap + ROTR 9)

      // Ch(e, f, g) (optimized the same way as SHA-1)
      ch_hi = (g_hi ^ (e_hi & (f_hi ^ g_hi))) >>> 0
      ch_lo = (g_lo ^ (e_lo & (f_lo ^ g_lo))) >>> 0

      // Sum0(a) = ROTR 28(a) ^ ROTR 34(a) ^ ROTR 39(a)
      s0_hi = (
        ((a_hi >>> 28) | (a_lo << 4)) // ROTR 28
        ^ ((a_lo >>> 2) | (a_hi << 30)) // ROTR 34/(swap + ROTR 2)
        ^ ((a_lo >>> 7) | (a_hi << 25))) >>> 0 // ROTR 39/(swap + ROTR 7)
      s0_lo = (
        ((a_hi << 4) | (a_lo >>> 28)) // ROTR 28
        ^ ((a_lo << 30) | (a_hi >>> 2)) // ROTR 34/(swap + ROTR 2)
        ^ ((a_lo << 25) | (a_hi >>> 7))) >>> 0 // ROTR 39/(swap + ROTR 7)

      // Maj(a, b, c) (optimized the same way as SHA-1)
      maj_hi = ((a_hi & b_hi) | (c_hi & (a_hi ^ b_hi))) >>> 0
      maj_lo = ((a_lo & b_lo) | (c_lo & (a_lo ^ b_lo))) >>> 0

      // main algorithm
      // t1 = (h + s1 + ch + _k[i] + _w[i]) modulo 2^64 (carry lo overflow)
      lo = (h_lo + s1_lo + ch_lo + _k[i][1] + w[i][1])
      t1_hi = (h_hi + s1_hi + ch_hi + _k[i][0] + w[i][0]
        + ((lo / 0x100000000) >>> 0)) >>> 0
      t1_lo = lo >>> 0

      // t2 = s0 + maj modulo 2^64 (carry lo overflow)
      lo = s0_lo + maj_lo
      t2_hi = (s0_hi + maj_hi + ((lo / 0x100000000) >>> 0)) >>> 0
      t2_lo = lo >>> 0

      h_hi = g_hi
      h_lo = g_lo

      g_hi = f_hi
      g_lo = f_lo

      f_hi = e_hi
      f_lo = e_lo

      // e = (d + t1) modulo 2^64 (carry lo overflow)
      lo = d_lo + t1_lo
      e_hi = (d_hi + t1_hi + ((lo / 0x100000000) >>> 0)) >>> 0
      e_lo = lo >>> 0

      d_hi = c_hi
      d_lo = c_lo

      c_hi = b_hi
      c_lo = b_lo

      b_hi = a_hi
      b_lo = a_lo

      // a = (t1 + t2) modulo 2^64 (carry lo overflow)
      lo = t1_lo + t2_lo
      a_hi = (t1_hi + t2_hi + ((lo / 0x100000000) >>> 0)) >>> 0
      a_lo = lo >>> 0
    }

    // update hash state (additional modulo 2^64)
    lo = s[0][1] + a_lo
    s[0][0] = (s[0][0] + a_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[0][1] = lo >>> 0

    lo = s[1][1] + b_lo
    s[1][0] = (s[1][0] + b_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[1][1] = lo >>> 0

    lo = s[2][1] + c_lo
    s[2][0] = (s[2][0] + c_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[2][1] = lo >>> 0

    lo = s[3][1] + d_lo
    s[3][0] = (s[3][0] + d_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[3][1] = lo >>> 0

    lo = s[4][1] + e_lo
    s[4][0] = (s[4][0] + e_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[4][1] = lo >>> 0

    lo = s[5][1] + f_lo
    s[5][0] = (s[5][0] + f_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[5][1] = lo >>> 0

    lo = s[6][1] + g_lo
    s[6][0] = (s[6][0] + g_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[6][1] = lo >>> 0

    lo = s[7][1] + h_lo
    s[7][0] = (s[7][0] + h_hi + ((lo / 0x100000000) >>> 0)) >>> 0
    s[7][1] = lo >>> 0

    len -= 128
  }
}
