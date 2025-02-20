/**
 * Secure Hash Algorithm with 256-bit digest (SHA-256) implementation.
 *
 * See FIPS 180-2 for details.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2015 Digital Bazaar, Inc.
 */

import { createBuffer, fillString } from './utils'

export const sha256 = {}

/**
 * Creates a SHA-256 message digest object.
 *
 * @return a message digest object.
 */
sha256.create = function () {
  // do initialization as necessary
  if (!_initialized) {
    _init()
  }

  // SHA-256 state contains eight 32-bit integers
  let _state = null

  // input buffer
  let _input = createBuffer()

  // used for word storage
  const _w = Array.from({ length: 64 })

  // message digest object
  const md = {
    algorithm: 'sha256',
    blockLength: 64,
    digestLength: 32,
    // 56-bit length of message so far (does not including padding)
    messageLength: 0,
    // true message length
    fullMessageLength: null,
    // size of message length in bytes
    messageLengthSize: 8,
  }

  /**
   * Starts the digest.
   *
   * @return this digest object.
   */
  md.start = function () {
    // up to 56-bit message length for convenience
    md.messageLength = 0

    // full message length (set md.messageLength64 for backwards-compatibility)
    md.fullMessageLength = md.messageLength64 = []
    const int32s = md.messageLengthSize / 4
    for (let i = 0; i < int32s; ++i) {
      md.fullMessageLength.push(0)
    }
    _input = createBuffer()
    _state = {
      h0: 0x6A09E667,
      h1: 0xBB67AE85,
      h2: 0x3C6EF372,
      h3: 0xA54FF53A,
      h4: 0x510E527F,
      h5: 0x9B05688C,
      h6: 0x1F83D9AB,
      h7: 0x5BE0CD19,
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
    _update(_state, _w, _input)

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
    add the appropriate SHA-256 padding. Then we do the final update
    on a copy of the state so that if the user wants to get
    intermediate digests they can do so. */

    /* Determine the number of bytes that must be added to the message
    to ensure its length is congruent to 448 mod 512. In other words,
    the data to be digested must be a multiple of 512 bits (or 128 bytes).
    This data includes the message, some padding, and the length of the
    message. Since the length of the message will be encoded as 8 bytes (64
    bits), that means that the last segment of the data must have 56 bytes
    (448 bits) of message and padding. Therefore, the length of the message
    plus the padding must be congruent to 448 mod 512 because
    512 - 128 = 448.

    In order to fill up the message length it must be filled with
    padding that begins with 1 bit followed by all 0 bits. Padding
    must *always* be present, so if the message length is already
    congruent to 448 mod 512, then 512 padding bits must be added. */

    const finalBlock = createBuffer()
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
    for (let i = 0; i < md.fullMessageLength.length - 1; ++i) {
      next = md.fullMessageLength[i + 1] * 8
      carry = (next / 0x100000000) >>> 0
      bits += carry
      finalBlock.putInt32(bits >>> 0)
      bits = next >>> 0
    }
    finalBlock.putInt32(bits)

    const s2 = {
      h0: _state.h0,
      h1: _state.h1,
      h2: _state.h2,
      h3: _state.h3,
      h4: _state.h4,
      h5: _state.h5,
      h6: _state.h6,
      h7: _state.h7,
    }
    _update(s2, _w, finalBlock)
    const rval = createBuffer()
    rval.putInt32(s2.h0)
    rval.putInt32(s2.h1)
    rval.putInt32(s2.h2)
    rval.putInt32(s2.h3)
    rval.putInt32(s2.h4)
    rval.putInt32(s2.h5)
    rval.putInt32(s2.h6)
    rval.putInt32(s2.h7)
    return rval
  }

  return md
}

// sha-256 padding bytes not initialized yet
var _padding = null
var _initialized = false

// table of constants
let _k = null

/**
 * Initializes the constant tables.
 */
function _init() {
  // create padding
  _padding = String.fromCharCode(128)
  _padding += fillString(String.fromCharCode(0x00), 64)

  // create K table for SHA-256
  _k = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
  ]

  // now initialized
  _initialized = true
}

/**
 * Updates a SHA-256 state with the given byte buffer.
 *
 * @param s the SHA-256 state to update.
 * @param w the array to use to store words.
 * @param bytes the byte buffer to update with.
 */
function _update(s, w, bytes) {
  // consume 512 bit (64 byte) chunks
  let t1, t2, s0, s1, ch, maj, i, a, b, c, d, e, f, g, h
  let len = bytes.length()
  while (len >= 64) {
    // the w array will be populated with sixteen 32-bit big-endian words
    // and then extended into 64 32-bit words according to SHA-256
    for (i = 0; i < 16; ++i) {
      w[i] = bytes.getInt32()
    }
    for (; i < 64; ++i) {
      // XOR word 2 words ago rot right 17, rot right 19, shft right 10
      t1 = w[i - 2]
      t1
        = ((t1 >>> 17) | (t1 << 15))
          ^ ((t1 >>> 19) | (t1 << 13))
          ^ (t1 >>> 10)
      // XOR word 15 words ago rot right 7, rot right 18, shft right 3
      t2 = w[i - 15]
      t2
        = ((t2 >>> 7) | (t2 << 25))
          ^ ((t2 >>> 18) | (t2 << 14))
          ^ (t2 >>> 3)
      // sum(t1, word 7 ago, t2, word 16 ago) modulo 2^32
      w[i] = (t1 + w[i - 7] + t2 + w[i - 16]) | 0
    }

    // initialize hash value for this chunk
    a = s.h0
    b = s.h1
    c = s.h2
    d = s.h3
    e = s.h4
    f = s.h5
    g = s.h6
    h = s.h7

    // round function
    for (i = 0; i < 64; ++i) {
      // Sum1(e)
      s1
        = ((e >>> 6) | (e << 26))
          ^ ((e >>> 11) | (e << 21))
          ^ ((e >>> 25) | (e << 7))
      // Ch(e, f, g) (optimized the same way as SHA-1)
      ch = g ^ (e & (f ^ g))
      // Sum0(a)
      s0
        = ((a >>> 2) | (a << 30))
          ^ ((a >>> 13) | (a << 19))
          ^ ((a >>> 22) | (a << 10))
      // Maj(a, b, c) (optimized the same way as SHA-1)
      maj = (a & b) | (c & (a ^ b))

      // main algorithm
      t1 = h + s1 + ch + _k[i] + w[i]
      t2 = s0 + maj
      h = g
      g = f
      f = e
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      // can't truncate with `| 0`
      e = (d + t1) >>> 0
      d = c
      c = b
      b = a
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      // can't truncate with `| 0`
      a = (t1 + t2) >>> 0
    }

    // update hash state
    s.h0 = (s.h0 + a) | 0
    s.h1 = (s.h1 + b) | 0
    s.h2 = (s.h2 + c) | 0
    s.h3 = (s.h3 + d) | 0
    s.h4 = (s.h4 + e) | 0
    s.h5 = (s.h5 + f) | 0
    s.h6 = (s.h6 + g) | 0
    s.h7 = (s.h7 + h) | 0
    len -= 64
  }
}
