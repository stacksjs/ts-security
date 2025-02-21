/**
 * Message Digest Algorithm 5 with 128-bit digest (MD5) implementation.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */

import { ByteStringBuffer, createBuffer, encodeUtf8, fillString } from './utils'

interface MD5State {
  h0: number
  h1: number
  h2: number
  h3: number
}

interface MessageDigest {
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

interface MD5 {
  create: () => MessageDigest
}

type LengthArray = [number, number]

/**
 * Creates an MD5 message digest object.
 *
 * @return a message digest object.
 */
function create(): MessageDigest {
  // do initialization as necessary
  if (!_initialized) {
    _init()
  }

  // MD5 state contains four 32-bit integers
  let _state: MD5State | null = null

  // input buffer
  let _input = createBuffer()

  // used for word storage
  const _w: number[] = Array.from({ length: 16 }).fill(0)

  // message digest object
  const md: MessageDigest = {
    algorithm: 'md5',
    blockLength: 64,
    digestLength: 16,
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
      const lenArray: LengthArray = [Math.floor(len / 0x100000000) >>> 0, len >>> 0]
      for (let i = md.fullMessageLength.length - 1; i >= 0; --i) {
        md.fullMessageLength[i] += lenArray[1]
        lenArray[1] = lenArray[0] + ((md.fullMessageLength[i] / 0x100000000) >>> 0)
        md.fullMessageLength[i] = md.fullMessageLength[i] >>> 0
        lenArray[0] = (lenArray[1] / 0x100000000) >>> 0
      }

      // add bytes to input buffer
      if (msg instanceof ByteStringBuffer) {
        _input.putBytes(msg.bytes())
      }
      else {
        _input.putBytes(msg)
      }

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
      add the appropriate MD5 padding. Then we do the final update
      on a copy of the state so that if the user wants to get
      intermediate digests they can do so. */

      const finalBlock = createBuffer()
      finalBlock.putBytes(_input.bytes())

      // compute remaining size to be digested (include message length size)
      const remaining = (
        md.fullMessageLength[md.fullMessageLength.length - 1]
        + md.messageLengthSize
      )

      // add padding for overflow blockSize - overflow
      // _padding starts with 1 byte with first bit is set (byte value 128), then
      // there may be up to (blockSize - 1) other pad bytes
      const overflow = remaining & (md.blockLength - 1)
      finalBlock.putBytes(_padding!.substr(0, md.blockLength - overflow))

      // serialize message length in bits in little-endian order; since length
      // is stored in bytes we multiply by 8 and add carry
      let bits: number
      let carry = 0
      for (let i = md.fullMessageLength.length - 1; i >= 0; --i) {
        bits = md.fullMessageLength[i] * 8 + carry
        carry = (bits / 0x100000000) >>> 0
        finalBlock.putInt32Le(bits >>> 0)
      }

      const s2: MD5State = {
        h0: _state!.h0,
        h1: _state!.h1,
        h2: _state!.h2,
        h3: _state!.h3,
      }
      _update(s2, _w, finalBlock)
      const rval = createBuffer()
      rval.putInt32Le(s2.h0)
      rval.putInt32Le(s2.h1)
      rval.putInt32Le(s2.h2)
      rval.putInt32Le(s2.h3)
      return rval
    },
  }

  // start digest automatically for first time
  md.start()

  return md
}

// padding, constant tables for calculating md5
let _padding: string | null = null
let _initialized = false
const _g: number[] = []
const _r: number[] = []
const _k: number[] = []

/**
 * Initializes the constant tables.
 */
function _init() {
  // create padding
  _padding = String.fromCharCode(128)
  _padding += fillString(String.fromCharCode(0x00), 64)

  // g values
  _g.push(
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    1,
    6,
    11,
    0,
    5,
    10,
    15,
    4,
    9,
    14,
    3,
    8,
    13,
    2,
    7,
    12,
    5,
    8,
    11,
    14,
    1,
    4,
    7,
    10,
    13,
    0,
    3,
    6,
    9,
    12,
    15,
    2,
    0,
    7,
    14,
    5,
    12,
    3,
    10,
    1,
    8,
    15,
    6,
    13,
    4,
    11,
    2,
    9,
  )

  // rounds table
  _r.push(
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
  )

  // get the result of abs(sin(i + 1)) as a 32-bit integer
  for (let i = 0; i < 64; ++i) {
    _k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000)
  }

  // now initialized
  _initialized = true
}

/**
 * Updates an MD5 state with the given byte buffer.
 *
 * @param s the MD5 state to update.
 * @param w the array to use to store words.
 * @param bytes the byte buffer to update with.
 */
function _update(s: MD5State, w: number[], bytes: ByteStringBuffer): void {
  // consume 512 bit (64 byte) chunks
  let t: number, a: number, b: number, c: number, d: number, f: number, r: number, i: number
  let len = bytes.length()
  while (len >= 64) {
    // initialize hash value for this chunk
    a = s.h0
    b = s.h1
    c = s.h2
    d = s.h3

    // round 1
    for (i = 0; i < 16; ++i) {
      w[i] = bytes.getInt32Le()
      f = d ^ (b & (c ^ d))
      t = (a + f + _k[i] + w[i])
      r = _r[i]
      a = d
      d = c
      c = b
      b += (t << r) | (t >>> (32 - r))
    }
    // round 2
    for (; i < 32; ++i) {
      f = c ^ (d & (b ^ c))
      t = (a + f + _k[i] + w[_g[i]])
      r = _r[i]
      a = d
      d = c
      c = b
      b += (t << r) | (t >>> (32 - r))
    }
    // round 3
    for (; i < 48; ++i) {
      f = b ^ c ^ d
      t = (a + f + _k[i] + w[_g[i]])
      r = _r[i]
      a = d
      d = c
      c = b
      b += (t << r) | (t >>> (32 - r))
    }
    // round 4
    for (; i < 64; ++i) {
      f = c ^ (b | ~d)
      t = (a + f + _k[i] + w[_g[i]])
      r = _r[i]
      a = d
      d = c
      c = b
      b += (t << r) | (t >>> (32 - r))
    }

    // update hash state
    s.h0 = (s.h0 + a) | 0
    s.h1 = (s.h1 + b) | 0
    s.h2 = (s.h2 + c) | 0
    s.h3 = (s.h3 + d) | 0

    len -= 64
  }
}

export const md5: MD5 = {
  create,
}
