/**
 * Secure Hash Algorithm with 160-bit digest (SHA-1) implementation.
 * This implementation follows the FIPS 180-2 specification and is based on the
 * node-forge implementation.
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

  // used for word storage
  const _w: number[] = new Array(80).fill(0)

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
     * Updates the digest with the given message input.
     *
     * @param msg the message input to update with.
     * @param encoding the encoding to use (default: 'raw', other: 'utf8').
     *
     * @return this digest object.
     */
    update(msg: string | ByteStringBuffer, encoding?: string) {
      if (!msg) {
        return md
      }

      if (encoding === 'utf8') {
        msg = encodeUtf8(msg as string)
      }

      // update message length
      const len = msg instanceof ByteStringBuffer ? msg.length() : msg.length
      md.messageLength += len
      const lenArr = [(len / 0x100000000) >>> 0, len >>> 0]
      for (let i = md.fullMessageLength.length - 1; i >= 0; --i) {
        md.fullMessageLength[i] += lenArr[1]
        lenArr[1] = lenArr[0] + ((md.fullMessageLength[i] / 0x100000000) >>> 0)
        md.fullMessageLength[i] = md.fullMessageLength[i] >>> 0
        lenArr[0] = ((lenArr[1] / 0x100000000) >>> 0)
      }

      // add bytes to input buffer
      _input.putBytes(msg instanceof ByteStringBuffer ? msg.bytes() : msg)

      // process bytes
      _update(_state!, _w, _input)

      // compact input buffer every 2K bytes
      if (_input.length() > 2048) {
        _input = createBuffer(_input.bytes())
      }

      return md
    },

    /**
     * Produces the digest.
     *
     * @return a byte buffer containing the digest value.
     */
    digest() {
      const finalBlock = createBuffer()
      finalBlock.putBytes(_input.bytes())

      // compute remaining size to be digested (include message length size)
      const remaining = (
        md.fullMessageLength[md.fullMessageLength.length - 1] +
        md.messageLengthSize
      )

      // add padding for overflow blockSize - overflow
      const overflow = remaining & (md.blockLength - 1)
      if (_padding === null) {
        throw new Error('SHA-1 padding not initialized')
      }

      // add padding
      const padLength = overflow < 56 ? 56 - overflow : 120 - overflow
      finalBlock.putBytes(_padding.substr(0, padLength))

      // serialize message length in bits in big-endian order
      let bits = md.fullMessageLength[0] * 8
      const finalState = {
        h0: _state!.h0,
        h1: _state!.h1,
        h2: _state!.h2,
        h3: _state!.h3,
        h4: _state!.h4,
      }

      for (let i = 0; i < md.fullMessageLength.length - 1; ++i) {
        const next = md.fullMessageLength[i + 1] * 8
        const carry = (next / 0x100000000) >>> 0
        bits += carry
        finalBlock.putInt32(bits >>> 0)
        bits = next >>> 0
      }
      finalBlock.putInt32(bits)

      // update state one last time
      _update(finalState, _w, finalBlock)

      // build final hash value
      const rval = createBuffer()
      rval.putInt32(finalState.h0)
      rval.putInt32(finalState.h1)
      rval.putInt32(finalState.h2)
      rval.putInt32(finalState.h3)
      rval.putInt32(finalState.h4)

      // reset state for next use
      _input = createBuffer()
      _state = {
        h0: 0x67452301,
        h1: 0xEFCDAB89,
        h2: 0x98BADCFE,
        h3: 0x10325476,
        h4: 0xC3D2E1F0,
      }

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
  let len = bytes.length()
  while (len >= 64) {
    // initialize hash value for this chunk
    a = s.h0
    b = s.h1
    c = s.h2
    d = s.h3
    e = s.h4

    // The w array will be populated with sixteen 32-bit big-endian words
    for (let i = 0; i < 16; ++i) {
      w[i] = bytes.getInt32()
    }

    // Extend into 80 32-bit words
    for (let i = 16; i < 80; ++i) {
      t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
      w[i] = ((t << 1) | (t >>> 31)) >>> 0
    }

    // Round function
    for (let i = 0; i < 80; ++i) {
      if (i < 20) {
        f = (b & c) | ((~b) & d)
        t = 0x5A827999
      } else if (i < 40) {
        f = b ^ c ^ d
        t = 0x6ED9EBA1
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d)
        t = 0x8F1BBCDC
      } else {
        f = b ^ c ^ d
        t = 0xCA62C1D6
      }

      t = (((a << 5) | (a >>> 27)) + f + e + t + w[i]) >>> 0
      e = d
      d = c
      c = ((b << 30) | (b >>> 2)) >>> 0
      b = a
      a = t
    }

    // update state
    s.h0 = (s.h0 + a) >>> 0
    s.h1 = (s.h1 + b) >>> 0
    s.h2 = (s.h2 + c) >>> 0
    s.h3 = (s.h3 + d) >>> 0
    s.h4 = (s.h4 + e) >>> 0

    len -= 64
  }
}

export const sha1: { create: typeof create } = {
  create,
}

export default sha1
