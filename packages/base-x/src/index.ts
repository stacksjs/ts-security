// base-x encoding / decoding
// Copyright (c) 2018 base-x contributors
// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
// Distributed under the MIT software license, see the accompanying
// @see http://www.opensource.org/licenses/mit-license.php

// Common alphabets and their bases
export const ALPHABETS = {
  BASE2: '01',
  BASE8: '01234567',
  BASE11: '0123456789a',
  BASE16: '0123456789abcdef',
  BASE32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
  BASE32Z: 'ybndrfg8ejkmcpqxot1uwisza345h769',
  BASE36: '0123456789abcdefghijklmnopqrstuvwxyz',
  BASE58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
  BASE62: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
  BASE64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  BASE67: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~',
} as const

// Type definitions
export type KnownAlphabet = typeof ALPHABETS[keyof typeof ALPHABETS]
export type Alphabet = KnownAlphabet | string

/**
 * Interface for base-x encoding and decoding.
 *
 * @example
 * ```ts
 * import { base64, base } from 'ts-security'
 *
 * // const base64 = base(ALPHABETS.BASE64)
 * const encoded = base64.encode(new Uint8Array([1, 2, 3]))
 * const decoded = base64.decode(encoded)
 * ```
 *
 * @example
 */
export interface BaseConverter {
  /**
   * Encodes a Uint8Array or string into a base-x encoded string.
   *
   * @param input - The input to encode.
   * @param maxline - The maximum line length for multi-line encoding.
   * @returns The base-x encoded string.
   */
  encode: (input: Uint8Array | string, maxline?: number) => string
  /**
   * Decodes a base-x encoded string into a Uint8Array.
   *
   * @param input - The base-x encoded string to decode.
   * @param maxline - The maximum line length for multi-line decoding.
   * @returns The decoded Uint8Array.
   */
  decode: (input: string, maxline?: number) => Uint8Array
}

/**
 * Creates a base converter for a given alphabet.
 *
 * @param ALPHABET - The alphabet to use for encoding and decoding.
 * @returns A BaseConverter object with encode and decode methods.
 */
export function base(ALPHABET: Alphabet = ALPHABETS.BASE58): BaseConverter {
  if (ALPHABET.length >= 255)
    throw new TypeError('Alphabet too long')

  const BASE_MAP = new Uint8Array(256)
  for (let j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255
  }

  for (let i = 0; i < ALPHABET.length; i++) {
    const x = ALPHABET.charAt(i)
    const xc = x.charCodeAt(0)

    if (BASE_MAP[xc] !== 255)
      throw new TypeError(`${x} is ambiguous`)

    BASE_MAP[xc] = i
  }

  const BASE = ALPHABET.length
  const LEADER = ALPHABET.charAt(0)
  const FACTOR = Math.log(BASE) / Math.log(256) // log(BASE) / log(256), rounded up
  const iFACTOR = Math.log(256) / Math.log(BASE) // log(256) / log(BASE), rounded up

  /**
   * Encodes a Uint8Array or string into a base-x encoded string.
   *
   * @param source - The input to encode.
   * @returns The base-x encoded string.
   */
  function encode(source: Uint8Array | string): string {
    // eslint-disable-next-line no-empty
    if (source instanceof Uint8Array) { }
    else if (ArrayBuffer.isView(source))
      source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    else if (Array.isArray(source))
      source = Uint8Array.from(source)

    if (!(source instanceof Uint8Array))
      throw new TypeError('Expected Uint8Array')

    if (source.length === 0)
      return ''

    // Skip & count leading zeroes.
    let zeroes = 0
    let length = 0
    let pbegin = 0
    const pend = source.length

    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++
      zeroes++
    }

    // Allocate enough space in big-endian base58 representation.
    const size = ((pend - pbegin) * iFACTOR + 1) >>> 0
    const b58 = new Uint8Array(size)

    // Process the bytes.
    while (pbegin !== pend) {
      let carry = source[pbegin]

      // Apply "b58 = b58 * 256 + ch".
      let i = 0
      for (let it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0
        b58[it1] = (carry % BASE) >>> 0
        carry = (carry / BASE) >>> 0
      }

      if (carry !== 0)
        throw new Error('Non-zero carry')

      length = i
      pbegin++
    }

    // Skip leading zeroes in base58 result.
    let it2 = size - length
    while (it2 !== size && b58[it2] === 0)
      it2++

    // Translate the result into a string.
    let str = LEADER.repeat(zeroes)
    for (; it2 < size; ++it2) str += ALPHABET.charAt(b58[it2])

    return str
  }

  /**
   * Decodes a base-x encoded string into a Uint8Array.
   *
   * @param source - The base-x encoded string to decode.
   * @returns The decoded Uint8Array.
   */
  function decode(source: string): Uint8Array {
    if (typeof source !== 'string')
      throw new TypeError('Expected String')

    if (source.length === 0)
      return new Uint8Array()

    let psz = 0

    // Skip and count leading '1's.
    let zeroes = 0
    let length = 0

    while (source[psz] === LEADER) {
      zeroes++
      psz++
    }

    // Allocate enough space in big-endian base256 representation.
    const size = (((source.length - psz) * FACTOR) + 1) >>> 0 // log(58) / log(256), rounded up.
    const b256 = new Uint8Array(size)

    // Process the characters.
    while (psz < source.length) {
      // Decode character
      let carry = BASE_MAP[source.charCodeAt(psz)]

      // Invalid character
      if (carry === 255)
        throw new Error('Non-base58 character')

      let i = 0
      for (let it3 = size - 1; (carry !== 0 || i < length) && (it3 !== -1); it3--, i++) {
        carry += (BASE * b256[it3]) >>> 0
        b256[it3] = (carry % 256) >>> 0
        carry = (carry / 256) >>> 0
      }

      if (carry !== 0)
        throw new Error('Non-zero carry')

      length = i
      psz++
    }

    // Skip leading zeroes in b256.
    let it4 = size - length
    while (it4 !== size && b256[it4] === 0) {
      it4++
    }

    const vch = new Uint8Array(zeroes + (size - it4))

    let j = zeroes
    while (it4 !== size) {
      vch[j++] = b256[it4++]
    }

    return vch
  }

  return {
    encode,
    decode,
  }
}

// Export pre-configured base converters
export const base64: BaseConverter = base(ALPHABETS.BASE64)
export const base58: BaseConverter = base(ALPHABETS.BASE58)
export const base32: BaseConverter = base(ALPHABETS.BASE32)
export const base32z: BaseConverter = base(ALPHABETS.BASE32Z)
export const base67: BaseConverter = base(ALPHABETS.BASE67)
export const base62: BaseConverter = base(ALPHABETS.BASE62)
export const base36: BaseConverter = base(ALPHABETS.BASE36)
export const base16: BaseConverter = base(ALPHABETS.BASE16)
export const base11: BaseConverter = base(ALPHABETS.BASE11)
export const base8: BaseConverter = base(ALPHABETS.BASE8)
export const base2: BaseConverter = base(ALPHABETS.BASE2)

// Export the base function as default
export default base
