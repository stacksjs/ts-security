/**
 * RC2 implementation.
 *
 * @author Stefan Siegl
 *
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 *
 * Information on the RC2 cipher is available from RFC #2268,
 * http://www.ietf.org/rfc/rfc2268.txt
 */

import { BlockCipher } from "./cipher";
import type { Algorithm, CipherOptions } from "./cipher";
import type { ByteStringBuffer } from "./utils";
import { createBuffer } from "./utils";

interface RC2Options extends CipherOptions {
  bits?: number;
}

const piTable = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
];

const s = [1, 2, 3, 5];

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
  return ((word << bits) & 0xffff) | ((word & 0xffff) >> (16 - bits));
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
  return ((word & 0xffff) >> bits) | ((word << (16 - bits)) & 0xffff);
};

/**
 * Perform RC2 key expansion as per RFC #2268, section 2.
 *
 * @param key variable-length user key (between 1 and 128 bytes)
 * @param effKeyBits number of effective key bits (default: 128)
 * @return the expanded RC2 key (ByteBuffer of 128 bytes)
 */
function expandKey(key: string | ByteStringBuffer, effKeyBits?: number): ByteStringBuffer {
  let keyBuffer: ByteStringBuffer;
  if (typeof key === 'string') {
    keyBuffer = createBuffer(key);
  } else {
    keyBuffer = key;
  }

  effKeyBits = effKeyBits || 128;

  /* introduce variables that match the names used in RFC #2268 */
  const L = keyBuffer;
  const T = keyBuffer.length();
  const T1 = effKeyBits;
  const T8 = Math.ceil(T1 / 8);
  const TM = 0xff >> (T1 & 0x07);
  let i: number;

  for (i = T; i < 128; i++) {
    const prevByte = L.at(i - 1) || 0;
    const tByte = L.at(i - T) || 0;
    L.putByte(piTable[(prevByte + tByte) & 0xff]);
  }

  L.setAt(128 - T8, piTable[L.at(128 - T8) & TM]);

  for (i = 127 - T8; i >= 0; i--) {
    const byte1 = L.at(i + 1) || 0;
    const byte8 = L.at(i + T8) || 0;
    L.setAt(i, piTable[byte1 ^ byte8]);
  }

  return L;
};

class RC2Algorithm implements Algorithm {
  name: string = 'RC2';
  mode: any; // Will be set by cipher modes
  private _init: boolean = false;
  private _expandedKey: ByteStringBuffer | null = null;
  private _bits: number = 128;

  initialize(options: RC2Options): void {
    if (this._init) return;

    const key = typeof options.key === 'string' ? createBuffer(options.key) : options.key;
    this._bits = options.bits || 128;
    this._expandedKey = expandKey(key, this._bits);
    this._init = true;
  }

  encrypt(input: number[], output: number[]): void {
    if (!this._expandedKey) return;

    let i: number;
    let j: number = 0;
    const K: number[] = [];

    for (i = 0; i < 64; i++) {
      K.push(this._expandedKey.getInt16Le());
    }

    // Copy input to output
    for (i = 0; i < input.length; i++) {
      output[i] = input[i];
    }

    // Perform encryption rounds
    for (i = 0; i < 4; i++) {
      output[i] = (output[i] + K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4]) +
        ((~output[(i + 3) % 4]) & output[(i + 1) % 4])) & 0xffff;
      output[i] = rol(output[i], s[i]);
      j++;
    }

    for (i = 0; i < 4; i++) {
      output[i] = (output[i] + K[output[(i + 3) % 4] & 63]) & 0xffff;
    }

    for (i = 0; i < 4; i++) {
      output[i] = (output[i] + K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4]) +
        ((~output[(i + 3) % 4]) & output[(i + 1) % 4])) & 0xffff;
      output[i] = rol(output[i], s[i]);
      j++;
    }
  }

  decrypt(input: number[], output: number[]): void {
    if (!this._expandedKey) return;

    let i: number;
    let j: number = 63;
    const K: number[] = [];

    for (i = 0; i < 64; i++) {
      K.push(this._expandedKey.getInt16Le());
    }

    // Copy input to output
    for (i = 0; i < input.length; i++) {
      output[i] = input[i];
    }

    // Perform decryption rounds
    for (i = 3; i >= 0; i--) {
      output[i] = ror(output[i], s[i]);
      output[i] = (output[i] - (K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4]) +
        ((~output[(i + 3) % 4]) & output[(i + 1) % 4]))) & 0xffff;
      j--;
    }

    for (i = 3; i >= 0; i--) {
      output[i] = (output[i] - K[output[(i + 3) % 4] & 63]) & 0xffff;
    }

    for (i = 3; i >= 0; i--) {
      output[i] = ror(output[i], s[i]);
      output[i] = (output[i] - (K[j] + (output[(i + 3) % 4] & output[(i + 2) % 4]) +
        ((~output[(i + 3) % 4]) & output[(i + 1) % 4]))) & 0xffff;
      j--;
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
  const algorithm = new RC2Algorithm();
  const cipher = new BlockCipher({
    algorithm,
    key,
    decrypt: !encrypt,
  });
  return cipher;
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
  const cipher = createEncryptionCipher(key, 128);
  cipher.start({ iv } as RC2Options);
  return cipher;
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
  return createCipher(key, bits, true);
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
  const cipher = createDecryptionCipher(key, 128);
  cipher.start({ iv } as RC2Options);
  return cipher;
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
  return createCipher(key, bits, false);
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
  createDecryptionCipher
}

export default rc2
