/**
 * Secure Hash Algorithm with 256-bit digest (SHA-256) implementation.
 *
 * This implementation follows FIPS 180-2 specification for SHA-256.
 * It provides a secure hash function that produces a 256-bit (32-byte) hash value
 * for any given input data.
 *
 * Key features:
 * 1. Implements the standard SHA-256 algorithm as specified in FIPS 180-2
 * 2. Processes input in 512-bit blocks
 * 3. Produces a 256-bit message digest
 * 4. Supports both synchronous and streaming operations
 * 5. Handles UTF-8 encoded input
 *
 * @author Chris Breuer
 */

import { ByteStringBuffer, createBuffer, encodeUtf8, fillString } from 'ts-security-utils'

// SHA-256 state interface
interface SHA256State {
  h0: number
  h1: number
  h2: number
  h3: number
  h4: number
  h5: number
  h6: number
  h7: number
}

// Message digest interface
interface MessageDigest {
  algorithm: string
  blockLength: number
  digestLength: number
  messageLength: number
  fullMessageLength: number[]
  messageLength64?: number[]
  messageLengthSize: number
  start: () => MessageDigest
  update: (msg: string | ByteStringBuffer, encoding?: string) => MessageDigest
  digest: () => ByteStringBuffer
}

// Internal state
let _initialized = false
let _padding: string | null = null
let _k: number[] | null = null

/**
 * Creates a SHA-256 message digest object.
 *
 * @returns a message digest object.
 */
export function createSHA256(): MessageDigest {
  // Initialize constants if necessary
  if (!_initialized) {
    _init()
  }

  // SHA-256 state contains eight 32-bit integers
  let _state: SHA256State | null = null

  // Input buffer
  let _input = createBuffer()

  // Used for word storage
  const _w = new Array(64).fill(0)

  // Message digest object
  const md: MessageDigest = {
    algorithm: 'sha256',
    blockLength: 64,
    digestLength: 32,
    messageLength: 0,
    fullMessageLength: [],
    messageLengthSize: 8,

    /**
     * Starts the digest.
     *
     * @returns this digest object.
     */
    start() {
      // Reset message length
      md.messageLength = 0
      md.fullMessageLength = []
      const int32s = md.messageLengthSize / 4
      for (let i = 0; i < int32s; ++i) {
        md.fullMessageLength.push(0)
      }

      // Reset input buffer
      _input = createBuffer()

      // Reset state
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
    },

    /**
     * Updates the digest with the given message input.
     *
     * @param msg - The message input to update with.
     * @param encoding - The encoding to use (default: 'raw', other: 'utf8').
     * @returns this digest object.
     */
    update(msg: string | ByteStringBuffer, encoding?: string) {
      if (!msg) {
        return md
      }

      // Handle UTF-8 encoding
      if (encoding === 'utf8') {
        msg = encodeUtf8(msg as string)
      }

      // Update message length
      const len = msg instanceof ByteStringBuffer ? msg.length() : msg.length
      md.messageLength += len
      const lenArr = [Math.floor(len / 0x100000000), len >>> 0]

      for (let i = md.fullMessageLength.length - 1; i >= 0; --i) {
        md.fullMessageLength[i] += lenArr[1]
        lenArr[1] = lenArr[0] + ((md.fullMessageLength[i] / 0x100000000) >>> 0)
        md.fullMessageLength[i] = md.fullMessageLength[i] >>> 0
        lenArr[0] = ((lenArr[1] / 0x100000000) >>> 0)
      }

      // Add bytes to input buffer
      _input.putBytes(msg instanceof ByteStringBuffer ? msg.bytes() : msg)

      // Process bytes
      _update(_state!, _w, _input)

      // Compact input buffer every 2K bytes
      if (_input.length() > 2048) {
        _input = createBuffer(_input.bytes())
      }

      return md
    },

    /**
     * Produces the digest.
     *
     * @returns a byte buffer containing the digest value.
     */
    digest() {
      const finalBlock = createBuffer()
      finalBlock.putBytes(_input.bytes())

      // Compute remaining size to be digested (include message length size)
      const remaining = (
        md.fullMessageLength[md.fullMessageLength.length - 1]
        + md.messageLengthSize
      )

      // Add padding
      const overflow = remaining & (md.blockLength - 1)
      finalBlock.putBytes(_padding!.substr(0, md.blockLength - overflow))

      // Serialize message length in bits in big-endian order
      let bits = md.fullMessageLength[0] * 8
      const finalState = {
        h0: _state!.h0,
        h1: _state!.h1,
        h2: _state!.h2,
        h3: _state!.h3,
        h4: _state!.h4,
        h5: _state!.h5,
        h6: _state!.h6,
        h7: _state!.h7,
      }

      for (let i = 0; i < md.fullMessageLength.length - 1; ++i) {
        const next = md.fullMessageLength[i + 1] * 8
        const carry = (next / 0x100000000) >>> 0
        bits += carry
        finalBlock.putInt32(bits >>> 0)
        bits = next >>> 0
      }
      finalBlock.putInt32(bits)

      // Final update
      _update(finalState, _w, finalBlock)

      // Build final hash value
      const rval = createBuffer()
      rval.putInt32(finalState.h0)
      rval.putInt32(finalState.h1)
      rval.putInt32(finalState.h2)
      rval.putInt32(finalState.h3)
      rval.putInt32(finalState.h4)
      rval.putInt32(finalState.h5)
      rval.putInt32(finalState.h6)
      rval.putInt32(finalState.h7)

      return rval
    },
  }

  // Start digest automatically for first time
  return md.start()
}

/**
 * Initializes the constant tables.
 */
function _init(): void {
  // Create padding
  _padding = String.fromCharCode(128)
  _padding += fillString(String.fromCharCode(0x00), 64)

  // Create K table for SHA-256
  _k = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
  ]

  _initialized = true
}

/**
 * Updates a SHA-256 state with the given byte buffer.
 *
 * @param s - The SHA-256 state to update.
 * @param w - The array to use to store words.
 * @param bytes - The byte buffer to update with.
 */
function _update(s: SHA256State, w: number[], bytes: ByteStringBuffer): void {
  // Consume 512 bit (64 byte) chunks
  let t1: number, t2: number, s0: number, s1: number, ch: number, maj: number
  let a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number
  let len = bytes.length()

  while (len >= 64) {
    // Initialize hash value for this chunk
    a = s.h0
    b = s.h1
    c = s.h2
    d = s.h3
    e = s.h4
    f = s.h5
    g = s.h6
    h = s.h7

    // The w array will be populated with sixteen 32-bit big-endian words
    for (let i = 0; i < 16; ++i) {
      w[i] = bytes.getInt32()
    }

    // Extend into 64 32-bit words
    for (let i = 16; i < 64; ++i) {
      // XOR word 2 words ago rot right 17, rot right 19, shft right 10
      t1 = w[i - 2]
      s1 = ((t1 >>> 17) | (t1 << 15)) ^
           ((t1 >>> 19) | (t1 << 13)) ^
           (t1 >>> 10)

      // XOR word 15 words ago rot right 7, rot right 18, shft right 3
      t2 = w[i - 15]
      s0 = ((t2 >>> 7) | (t2 << 25)) ^
           ((t2 >>> 18) | (t2 << 14)) ^
           (t2 >>> 3)

      // Sum(t1, word 7 ago, t2, word 16 ago) modulo 2^32
      w[i] = (s1 + w[i - 7] + s0 + w[i - 16]) | 0
    }

    // Round function
    for (let i = 0; i < 64; ++i) {
      // Sum1(e)
      s1 = ((e >>> 6) | (e << 26)) ^
           ((e >>> 11) | (e << 21)) ^
           ((e >>> 25) | (e << 7))

      // Ch(e, f, g) (optimized)
      ch = g ^ (e & (f ^ g))

      // Sum0(a)
      s0 = ((a >>> 2) | (a << 30)) ^
           ((a >>> 13) | (a << 19)) ^
           ((a >>> 22) | (a << 10))

      // Maj(a, b, c) (optimized)
      maj = (a & b) | (c & (a ^ b))

      // Main algorithm
      t1 = h + s1 + ch + _k![i] + w[i]
      t2 = s0 + maj

      h = g
      g = f
      f = e
      e = (d + t1) >>> 0
      d = c
      c = b
      b = a
      a = (t1 + t2) >>> 0
    }

    // Update hash state
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

/**
 * SHA-256 module interface.
 */
interface SHA256Module {
  create: () => MessageDigest
}

/**
 * SHA-256 module object.
 */
export const sha256: SHA256Module = {
  create: createSHA256,
}

export default sha256
