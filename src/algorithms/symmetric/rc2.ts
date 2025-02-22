/**
 * RC2 implementation.
 *
 * @author Stefan Siegl
 * @author Chris Breuer
 *
 * Information on the RC2 cipher is available from RFC #2268,
 * http://www.ietf.org/rfc/rfc2268.txt
 */

import type { Algorithm, CipherOptions } from './cipher'
import type { ByteStringBuffer } from '../../utils'
import { BlockCipher } from './cipher'
import { createBuffer } from '../../utils'

interface RC2Options extends CipherOptions {
  bits?: number
}

const piTable = [
  0xD9,
  0x78,
  0xF9,
  0xC4,
  0x19,
  0xDD,
  0xB5,
  0xED,
  0x28,
  0xE9,
  0xFD,
  0x79,
  0x4A,
  0xA0,
  0xD8,
  0x9D,
  0xC6,
  0x7E,
  0x37,
  0x83,
  0x2B,
  0x76,
  0x53,
  0x8E,
  0x62,
  0x4C,
  0x64,
  0x88,
  0x44,
  0x8B,
  0xFB,
  0xA2,
  0x17,
  0x9A,
  0x59,
  0xF5,
  0x87,
  0xB3,
  0x4F,
  0x13,
  0x61,
  0x45,
  0x6D,
  0x8D,
  0x09,
  0x81,
  0x7D,
  0x32,
  0xBD,
  0x8F,
  0x40,
  0xEB,
  0x86,
  0xB7,
  0x7B,
  0x0B,
  0xF0,
  0x95,
  0x21,
  0x22,
  0x5C,
  0x6B,
  0x4E,
  0x82,
  0x54,
  0xD6,
  0x65,
  0x93,
  0xCE,
  0x60,
  0xB2,
  0x1C,
  0x73,
  0x56,
  0xC0,
  0x14,
  0xA7,
  0x8C,
  0xF1,
  0xDC,
  0x12,
  0x75,
  0xCA,
  0x1F,
  0x3B,
  0xBE,
  0xE4,
  0xD1,
  0x42,
  0x3D,
  0xD4,
  0x30,
  0xA3,
  0x3C,
  0xB6,
  0x26,
  0x6F,
  0xBF,
  0x0E,
  0xDA,
  0x46,
  0x69,
  0x07,
  0x57,
  0x27,
  0xF2,
  0x1D,
  0x9B,
  0xBC,
  0x94,
  0x43,
  0x03,
  0xF8,
  0x11,
  0xC7,
  0xF6,
  0x90,
  0xEF,
  0x3E,
  0xE7,
  0x06,
  0xC3,
  0xD5,
  0x2F,
  0xC8,
  0x66,
  0x1E,
  0xD7,
  0x08,
  0xE8,
  0xEA,
  0xDE,
  0x80,
  0x52,
  0xEE,
  0xF7,
  0x84,
  0xAA,
  0x72,
  0xAC,
  0x35,
  0x4D,
  0x6A,
  0x2A,
  0x96,
  0x1A,
  0xD2,
  0x71,
  0x5A,
  0x15,
  0x49,
  0x74,
  0x4B,
  0x9F,
  0xD0,
  0x5E,
  0x04,
  0x18,
  0xA4,
  0xEC,
  0xC2,
  0xE0,
  0x41,
  0x6E,
  0x0F,
  0x51,
  0xCB,
  0xCC,
  0x24,
  0x91,
  0xAF,
  0x50,
  0xA1,
  0xF4,
  0x70,
  0x39,
  0x99,
  0x7C,
  0x3A,
  0x85,
  0x23,
  0xB8,
  0xB4,
  0x7A,
  0xFC,
  0x02,
  0x36,
  0x5B,
  0x25,
  0x55,
  0x97,
  0x31,
  0x2D,
  0x5D,
  0xFA,
  0x98,
  0xE3,
  0x8A,
  0x92,
  0xAE,
  0x05,
  0xDF,
  0x29,
  0x10,
  0x67,
  0x6C,
  0xBA,
  0xC9,
  0xD3,
  0x00,
  0xE6,
  0xCF,
  0xE1,
  0x9E,
  0xA8,
  0x2C,
  0x63,
  0x16,
  0x01,
  0x3F,
  0x58,
  0xE2,
  0x89,
  0xA9,
  0x0D,
  0x38,
  0x34,
  0x1B,
  0xAB,
  0x33,
  0xFF,
  0xB0,
  0xBB,
  0x48,
  0x0C,
  0x5F,
  0xB9,
  0xB1,
  0xCD,
  0x2E,
  0xC5,
  0xF3,
  0xDB,
  0x47,
  0xE5,
  0xA5,
  0x9C,
  0x77,
  0x0A,
  0xA6,
  0x20,
  0x68,
  0xFE,
  0x7F,
  0xC1,
  0xAD,
]

const s = [1, 2, 3, 5]

/**
 * Rotate a word left by given number of bits.
 *
 * Bits that are shifted out on the left are put back in on the right
 * hand side.
 *
 * @param word The word to shift left.
 * @param bits The number of bits to shift by.
 * @return The rotated word.
 */
function rol(word: number, bits: number): number {
  return ((word << bits) & 0xFFFF) | ((word & 0xFFFF) >> (16 - bits))
};

/**
 * Rotate a word right by given number of bits.
 *
 * Bits that are shifted out on the right are put back in on the left
 * hand side.
 *
 * @param word The word to shift right.
 * @param bits The number of bits to shift by.
 * @return The rotated word.
 */
function ror(word: number, bits: number): number {
  return ((word & 0xFFFF) >> bits) | ((word << (16 - bits)) & 0xFFFF)
};

/**
 * Perform RC2 key expansion as per RFC #2268, section 2.
 *
 * @param key variable-length user key (between 1 and 128 bytes)
 * @param effKeyBits number of effective key bits (default: 128)
 * @return the expanded RC2 key (ByteBuffer of 128 bytes)
 */
function expandKey(key: string | ByteStringBuffer, effKeyBits?: number): ByteStringBuffer {
  let keyBuffer: ByteStringBuffer
  if (typeof key === 'string') {
    keyBuffer = createBuffer(key)
  }
  else {
    keyBuffer = key
  }

  effKeyBits = effKeyBits || 128

  /* introduce variables that match the names used in RFC #2268 */
  const L = keyBuffer
  const T = keyBuffer.length()
  const T1 = effKeyBits
  const T8 = Math.ceil(T1 / 8)
  const TM = 0xFF >> (T1 & 0x07)
  let i: number

  for (i = T; i < 128; i++) {
    const prevByte = L.at(i - 1) || 0
    const tByte = L.at(i - T) || 0
    L.putByte(piTable[(prevByte + tByte) & 0xFF])
  }

  L.setAt(128 - T8, piTable[L.at(128 - T8) & TM])

  for (i = 127 - T8; i >= 0; i--) {
    const byte1 = L.at(i + 1) || 0
    const byte8 = L.at(i + T8) || 0
    L.setAt(i, piTable[byte1 ^ byte8])
  }

  return L
};

export class RC2Algorithm implements Algorithm {
  name: string = 'RC2'
  mode: any // Will be set by cipher modes
  private _init: boolean = false
  private _expandedKey: ByteStringBuffer | null = null
  private _bits: number = 128

  initialize(options: RC2Options): void {
    if (this._init)
      return

    const key = typeof options.key === 'string' ? createBuffer(options.key) : options.key
    this._bits = options.bits || 128
    this._expandedKey = expandKey(key, this._bits)
    this._init = true
  }

  encrypt(input: number[], output: number[]): void {
    if (!this._expandedKey)
      return

    let i: number
    let j: number = 0
    const K: number[] = []

    for (i = 0; i < 64; i++) {
      K.push(this._expandedKey.getInt16Le())
    }

    // Copy input to output
    for (i = 0; i < input.length; i++) {
      output[i] = input[i]
    }

    // Perform encryption rounds
    for (i = 0; i < 4; i++) {
      output[i] = (output[i] + K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4])
        + ((~output[(i + 3) % 4]) & output[(i + 1) % 4])) & 0xFFFF
      output[i] = rol(output[i], s[i])
      j++
    }

    for (i = 0; i < 4; i++) {
      output[i] = (output[i] + K[output[(i + 3) % 4] & 63]) & 0xFFFF
    }

    for (i = 0; i < 4; i++) {
      output[i] = (output[i] + K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4])
        + ((~output[(i + 3) % 4]) & output[(i + 1) % 4])) & 0xFFFF
      output[i] = rol(output[i], s[i])
      j++
    }
  }

  decrypt(input: number[], output: number[]): void {
    if (!this._expandedKey)
      return

    let i: number
    let j: number = 63
    const K: number[] = []

    for (i = 0; i < 64; i++) {
      K.push(this._expandedKey.getInt16Le())
    }

    // Copy input to output
    for (i = 0; i < input.length; i++) {
      output[i] = input[i]
    }

    // Perform decryption rounds
    for (i = 3; i >= 0; i--) {
      output[i] = ror(output[i], s[i])
      output[i] = (output[i] - (K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4])
        + ((~output[(i + 3) % 4]) & output[(i + 1) % 4]))) & 0xFFFF
      j--
    }

    for (i = 3; i >= 0; i--) {
      output[i] = (output[i] - K[output[(i + 3) % 4] & 63]) & 0xFFFF
    }

    for (i = 3; i >= 0; i--) {
      output[i] = ror(output[i], s[i])
      output[i] = (output[i] - (K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4])
        + ((~output[(i + 3) % 4]) & output[(i + 1) % 4]))) & 0xFFFF
      j--
    }
  }
}

/**
 * Creates a RC2 cipher object.
 *
 * @param key the symmetric key to use (as base for key generation).
 * @param bits the number of effective key bits.
 * @param encrypt false for decryption, true for encryption.
 *
 * @return the cipher.
 */
function createCipher(key: string | ByteStringBuffer, bits: number, encrypt: boolean): BlockCipher {
  const algorithm = new RC2Algorithm()
  const cipher = new BlockCipher({
    algorithm,
    key,
    decrypt: !encrypt,
  })
  return cipher
}

/**
 * Creates an RC2 cipher object to encrypt data in ECB or CBC mode using the
 * given symmetric key. The output will be stored in the 'output' member
 * of the returned cipher.
 *
 * The key and iv may be given as a string of bytes or a byte buffer.
 * The cipher is initialized to use 128 effective key bits.
 *
 * @param key the symmetric key to use.
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 *
 * @return the cipher.
 */
export function startEncrypting(key: string, iv: string, output: ByteStringBuffer): BlockCipher {
  const cipher = createEncryptionCipher(key, 128)
  cipher.start({ iv } as RC2Options)
  return cipher
}

/**
 * Creates an RC2 cipher object to encrypt data in ECB or CBC mode using the
 * given symmetric key.
 *
 * The key may be given as a string of bytes or a byte buffer.
 *
 * To start encrypting call start() on the cipher with an iv and optional
 * output buffer.
 *
 * @param key the symmetric key to use.
 *
 * @return the cipher.
 */
export function createEncryptionCipher(key: string, bits: number): BlockCipher {
  return createCipher(key, bits, true)
}

/**
 * Creates an RC2 cipher object to decrypt data in ECB or CBC mode using the
 * given symmetric key. The output will be stored in the 'output' member
 * of the returned cipher.
 *
 * The key and iv may be given as a string of bytes or a byte buffer.
 * The cipher is initialized to use 128 effective key bits.
 *
 * @param key the symmetric key to use.
 * @param iv the initialization vector to use.
 * @param output the buffer to write to, null to create one.
 *
 * @return the cipher.
 */
export function startDecrypting(key: string, iv: string, output: ByteStringBuffer): BlockCipher {
  const cipher = createDecryptionCipher(key, 128)
  cipher.start({ iv } as RC2Options)
  return cipher
}

/**
 * Creates an RC2 cipher object to decrypt data in ECB or CBC mode using the
 * given symmetric key.
 *
 * The key may be given as a string of bytes or a byte buffer.
 *
 * To start decrypting call start() on the cipher with an iv and optional
 * output buffer.
 *
 * @param key the symmetric key to use.
 *
 * @return the cipher.
 */
function createDecryptionCipher(key: string, bits: number): BlockCipher {
  return createCipher(key, bits, false)
}

export interface RC2 {
  expandKey: typeof expandKey
  createCipher: typeof createCipher
  startEncrypting: typeof startEncrypting
  createEncryptionCipher: typeof createEncryptionCipher
  startDecrypting: typeof startDecrypting
  createDecryptionCipher: typeof createDecryptionCipher
}

export const rc2: RC2 = {
  expandKey,
  createCipher,
  startEncrypting,
  createEncryptionCipher,
  startDecrypting,
  createDecryptionCipher,
}

export default rc2
