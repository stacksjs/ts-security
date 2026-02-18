import type { MessageDigest, SHA1State } from './types'
import type { ByteStringBuffer } from 'ts-security-utils'
import { createBuffer } from 'ts-security-utils'

/**
 * SHA-1 implementation
 * Based on the FIPS 180-1 standard
 */

// SHA-1 constants
const K = [
  0x5A827999, // 0 <= t <= 19
  0x6ED9EBA1, // 20 <= t <= 39
  0x8F1BBCDC, // 40 <= t <= 59
  0xCA62C1D6, // 60 <= t <= 79
]

// Initial hash state
const _initialState: SHA1State = {
  h0: 0x67452301,
  h1: 0xEFCDAB89,
  h2: 0x98BADCFE,
  h3: 0x10325476,
  h4: 0xC3D2E1F0,
}

/**
 * Left rotate a 32-bit number by shift bits
 */
function rotl(x: number, shift: number): number {
  return ((x << shift) | (x >>> (32 - shift))) >>> 0
}

/**
 * SHA-1 implementation
 */
export const sha1 = {
  /**
   * Creates a SHA-1 message digest object
   */
  create: (): MessageDigest => {
    // SHA-1 state
    let state: SHA1State = { ..._initialState }

    // Input buffer
    let _input = createBuffer()

    // Used for word operations
    const _w: number[] = new Array(80).fill(0)

    // Message digest object
    const md: MessageDigest = {
      algorithm: 'sha1',
      blockLength: 64,
      digestLength: 20,
      messageLength: 0,
      fullMessageLength: [0, 0],
      messageLengthSize: 8,

      /**
       * Resets the digest to its initial state
       */
      start() {
        state = { ..._initialState }
        _input = createBuffer()
        this.messageLength = 0
        this.fullMessageLength = [0, 0]
        return this
      },

      /**
       * Updates the digest with the given message
       * @param msg The message to update with
       * @param encoding The encoding of the message (default: 'raw')
       */
      update(msg: string | ByteStringBuffer, encoding = 'raw') {
        if (typeof msg === 'string') {
          if (encoding === 'utf8') {
            msg = createBuffer().putString(msg)
          }
          else {
            msg = createBuffer().putBytes(msg)
          }
        }

        // Update message length
        const len = (msg as ByteStringBuffer).length()
        this.messageLength += len
        const lenBits = len * 8
        this.fullMessageLength[0] += lenBits

        // Handle overflow
        if (this.fullMessageLength[0] < lenBits) {
          this.fullMessageLength[1]++
        }

        // Add message to input buffer
        _input.putBuffer(msg as ByteStringBuffer)

        // Process input in blocks
        _processInput()

        return this
      },

      /**
       * Produces the digest
       */
      digest() {
        // Create a copy of the input buffer
        const finalInput = _input.copy()

        // Create a copy of the current state
        const finalState = { ...state }

        // Create a copy of the message length
        const finalMessageLength = [...this.fullMessageLength]

        // Finalize the hash
        _finalizeHash(finalInput, finalState, finalMessageLength)

        // Create digest from state
        const digest = createBuffer()
        digest.putInt32(finalState.h0)
        digest.putInt32(finalState.h1)
        digest.putInt32(finalState.h2)
        digest.putInt32(finalState.h3)
        digest.putInt32(finalState.h4)

        return digest
      },
    }

    /**
     * Process the input buffer in blocks
     */
    function _processInput() {
      // Process as many blocks as possible
      while (_input.length() >= md.blockLength) {
        // Get current block
        const block = _input.getBytes(md.blockLength)
        _updateHash(block, state)
      }
    }

    /**
     * Update the hash with a block of data
     */
    function _updateHash(block: string, currentState: SHA1State) {
      // Initialize the 16 words
      let i
      for (i = 0; i < 16; ++i) {
        _w[i] = (
          (block.charCodeAt(i * 4) << 24)
          | (block.charCodeAt(i * 4 + 1) << 16)
          | (block.charCodeAt(i * 4 + 2) << 8)
          | block.charCodeAt(i * 4 + 3)
        ) >>> 0
      }

      // Extend the 16 words to 80 words
      for (i = 16; i < 80; ++i) {
        _w[i] = rotl(_w[i - 3] ^ _w[i - 8] ^ _w[i - 14] ^ _w[i - 16], 1)
      }

      // Initialize hash value for this chunk
      let a = currentState.h0
      let b = currentState.h1
      let c = currentState.h2
      let d = currentState.h3
      let e = currentState.h4

      // Main loop
      for (i = 0; i < 80; ++i) {
        let f, k

        if (i < 20) {
          f = (b & c) | ((~b) & d)
          k = K[0]
        }
        else if (i < 40) {
          f = b ^ c ^ d
          k = K[1]
        }
        else if (i < 60) {
          f = (b & c) | (b & d) | (c & d)
          k = K[2]
        }
        else {
          f = b ^ c ^ d
          k = K[3]
        }

        const temp = (rotl(a, 5) + f + e + k + _w[i]) >>> 0
        e = d
        d = c
        c = rotl(b, 30)
        b = a
        a = temp
      }

      // Add this chunk's hash to result so far
      currentState.h0 = (currentState.h0 + a) >>> 0
      currentState.h1 = (currentState.h1 + b) >>> 0
      currentState.h2 = (currentState.h2 + c) >>> 0
      currentState.h3 = (currentState.h3 + d) >>> 0
      currentState.h4 = (currentState.h4 + e) >>> 0
    }

    /**
     * Finalize the hash with the given input
     */
    function _finalizeHash(input: ByteStringBuffer, finalState: SHA1State, messageLength: number[]) {
      // Add padding
      const bitLength = messageLength[0] + (messageLength[1] * 0x100000000)
      const byteLength = Math.ceil(bitLength / 8)
      const padLength = md.blockLength - ((byteLength + md.messageLengthSize) % md.blockLength)

      // Add '1' bit and zeros
      input.putBytes(String.fromCharCode(0x80))

      // Add padding zeros
      for (let i = 0; i < padLength - 1; ++i) {
        input.putBytes(String.fromCharCode(0x00))
      }

      // Add length in bits as big-endian 64-bit integer
      input.putBytes(String.fromCharCode(
        (messageLength[1] >>> 24) & 0xFF,
        (messageLength[1] >>> 16) & 0xFF,
        (messageLength[1] >>> 8) & 0xFF,
        messageLength[1] & 0xFF,
        (messageLength[0] >>> 24) & 0xFF,
        (messageLength[0] >>> 16) & 0xFF,
        (messageLength[0] >>> 8) & 0xFF,
        messageLength[0] & 0xFF,
      ))

      // Process remaining blocks
      while (input.length() > 0) {
        const block = input.getBytes(md.blockLength)
        _updateHash(block, finalState)
      }
    }

    return md
  },
}
