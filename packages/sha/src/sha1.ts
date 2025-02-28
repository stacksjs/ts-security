/**
 * Secure Hash Algorithm with 160-bit digest (SHA-1) implementation.
 *
 * @author Chris Breuer
 */
import { ByteStringBuffer, createBuffer, encodeUtf8, fillString } from 'ts-security-utils'

export interface MessageDigest {
  algorithm: string
  blockLength: number
  digestLength: number
  messageLength: number
  fullMessageLength: number[]
  messageLengthSize: number
  messageLength64?: number[]
  start: () => MessageDigest
  update: (msg: string | ByteStringBuffer, encoding?: string) => MessageDigest
  digest: () => ByteStringBuffer
}

/**
 * Creates a SHA-1 message digest object.
 *
 * @return a message digest object.
 */
export function create(): MessageDigest {
  // do initialization as necessary
  if (!_initialized) {
    _init()
  }

  // SHA-1 state contains five 32-bit integers
  let _state: {
    h0: number
    h1: number
    h2: number
    h3: number
    h4: number
  } | null = null

  // input buffer
  let _input = createBuffer()

  // Fix array initialization with proper typing
  const _w: number[] = Array.from({ length: 80 }).fill(0)

  // message digest object
  const md: MessageDigest = {
    algorithm: 'sha1',
    blockLength: 64,
    digestLength: 20,
    // 56-bit length of message so far (does not including padding)
    messageLength: 0,
    // true message length
    fullMessageLength: [],
    // size of message length in bytes
    messageLengthSize: 8,

    /**
     * Starts the digest.
     *
     * @return this digest object.
     */
    start() {
      // up to 56-bit message length for convenience
      md.messageLength = 0

      // full message length (set md.messageLength64 for backwards-compatibility)
      md.fullMessageLength = []
      md.messageLength64 = []
      const int32s = md.messageLengthSize / 4
      for (let i = 0; i < int32s; ++i) {
        md.fullMessageLength.push(0)
      }
      _input = createBuffer()
      _state = {
        h0: 0x67452301,
        h1: 0xEFCDAB89,
        h2: 0x98BADCFE,
        h3: 0x10325476,
        h4: 0xC3D2E1F0,
      }
      return md
    },

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
    update(msg: string | ByteStringBuffer, encoding?: string) {
      if (encoding === 'utf8') {
        msg = encodeUtf8(msg as string)
      }

      // update message length
      const len = msg instanceof ByteStringBuffer ? msg.length() : msg.length
      md.messageLength += len
      const lenArr = [Math.floor(len / 0x100000000), len >>> 0]
      for (let i = md.fullMessageLength.length - 1; i >= 0; --i) {
        md.fullMessageLength[i] += lenArr[1]
        const carry = Math.floor(md.fullMessageLength[i] / 0x100000000)
        md.fullMessageLength[i] = md.fullMessageLength[i] >>> 0
        if (carry > 0 && i > 0) {
          md.fullMessageLength[i - 1] += carry
        }
      }

      // add bytes to input buffer
      _input.putBytes(msg instanceof ByteStringBuffer ? msg.bytes() : msg)

      // process bytes
      _update(_state!, _w, _input)

      // compact input buffer every 2K or if empty
      if (_input.read > 2048 || _input.length() === 0) {
        _input.compact()
      }

      return md
    },

    /**
     * Produces the digest.
     *
     * @return a byte buffer containing the digest value.
     */
    digest() {
      /* Note: Here we copy the remaining bytes in the input buffer and
      add the appropriate SHA-1 padding. Then we do the final update
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
      if (_padding === null) {
        throw new Error('SHA-1 padding not initialized')
      }
      finalBlock.putBytes(_padding.substr(0, md.blockLength - overflow))

      // serialize message length in bits in big-endian order; since length
      // is stored in bytes we multiply by 8 and add carry from next int
      let next: number, carry: number
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
        h0: _state!.h0,
        h1: _state!.h1,
        h2: _state!.h2,
        h3: _state!.h3,
        h4: _state!.h4,
      }
      _update(s2, _w, finalBlock)
      const rval = createBuffer()
      rval.putInt32(s2.h0)
      rval.putInt32(s2.h1)
      rval.putInt32(s2.h2)
      rval.putInt32(s2.h3)
      rval.putInt32(s2.h4)
      return rval
    },
  }

  // start digest automatically for first time
  md.start()

  return md
}

// sha-1 padding bytes not initialized yet
let _padding: string | null = null
let _initialized = false

/**
 * Initializes the constant tables.
 */
function _init() {
  // create padding
  _padding = String.fromCharCode(128)
  _padding += fillString(String.fromCharCode(0x00), 64)

  // now initialized
  _initialized = true
}

/**
 * Updates a SHA-1 state with the given byte buffer.
 *
 * @param s the SHA-1 state to update.
 * @param w the array to use to store words.
 * @param bytes the byte buffer to update with.
 */
function _update(s: {
  h0: number
  h1: number
  h2: number
  h3: number
  h4: number
}, w: number[], bytes: ByteStringBuffer) {
  // consume 512 bit (64 byte) chunks
  let t: number, a: number, b: number, c: number, d: number, e: number, f: number
  let i: number
  let len = bytes.length()
  while (len >= 64) {
    // the w array will be populated with sixteen 32-bit big-endian words
    // and then extended into 80 32-bit words according to SHA-1 algorithm
    // and for 32-79 using Max Locktyukhin's optimization

    // initialize hash value for this chunk
    a = s.h0
    b = s.h1
    c = s.h2
    d = s.h3
    e = s.h4

    // round 1
    for (i = 0; i < 16; ++i) {
      t = bytes.getInt32()
      w[i] = t
      f = d ^ (b & (c ^ d))
      t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + t
      e = d
      d = c
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = t
    }
    for (; i < 20; ++i) {
      t = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16])
      t = (t << 1) | (t >>> 31)
      w[i] = t
      f = d ^ (b & (c ^ d))
      t = ((a << 5) | (a >>> 27)) + f + e + 0x5A827999 + t
      e = d
      d = c
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = t
    }
    // round 2
    for (; i < 32; ++i) {
      t = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16])
      t = (t << 1) | (t >>> 31)
      w[i] = t
      f = b ^ c ^ d
      t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t
      e = d
      d = c
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = t
    }
    for (; i < 40; ++i) {
      t = (w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i - 32])
      t = (t << 2) | (t >>> 30)
      w[i] = t
      f = b ^ c ^ d
      t = ((a << 5) | (a >>> 27)) + f + e + 0x6ED9EBA1 + t
      e = d
      d = c
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = t
    }
    // round 3
    for (; i < 60; ++i) {
      t = (w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i - 32])
      t = (t << 2) | (t >>> 30)
      w[i] = t
      f = (b & c) | (d & (b ^ c))
      t = ((a << 5) | (a >>> 27)) + f + e + 0x8F1BBCDC + t
      e = d
      d = c
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = t
    }
    // round 4
    for (; i < 80; ++i) {
      t = (w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i - 32])
      t = (t << 2) | (t >>> 30)
      w[i] = t
      f = b ^ c ^ d
      t = ((a << 5) | (a >>> 27)) + f + e + 0xCA62C1D6 + t
      e = d
      d = c
      // `>>> 0` necessary to avoid iOS/Safari 10 optimization bug
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = t
    }

    // update hash state
    s.h0 = (s.h0 + a) | 0
    s.h1 = (s.h1 + b) | 0
    s.h2 = (s.h2 + c) | 0
    s.h3 = (s.h3 + d) | 0
    s.h4 = (s.h4 + e) | 0

    len -= 64
  }
}

export const sha1: { create: typeof create } = {
  create,
}
