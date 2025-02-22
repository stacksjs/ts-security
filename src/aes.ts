/**
 * Advanced Encryption Standard (AES) implementation.
 *
 * This implementation is based on the public domain library 'jscrypto'
 * which was written by:
 *
 * Emily Stark (estark@stanford.edu)
 * Mike Hamburg (mhamburg@stanford.edu)
 * Dan Boneh (dabo@cs.stanford.edu)
 *
 * Parts of this code are based on the OpenSSL implementation of AES:
 * http://www.openssl.org
 *
 * @author Dave Longley
 * @author Chris Breuer
 */

import type { Algorithm, BlockCipher } from './cipher'
import type { CipherMode, CipherModeOptions } from './cipher-modes'
import { createCipher, registerAlgorithm as registerCipherAlgorithm } from './cipher'
import { modes } from './cipher-modes'
import { ByteStringBuffer, createBuffer } from './utils'

// AES implementation types
type SubstitutionBox = number[]
type MixTable = number[][][]
type XTimeTable = number[]

interface AlgorithmOptions {
  key?: string | number[] | ByteStringBuffer
  decrypt?: boolean
}

/** AES implementation */
let init = false // not yet initialized
const Nb = 4 // number of words comprising the state (AES = 4)
let sbox: SubstitutionBox = [] // non-linear substitution table used in key expansion
let isbox: SubstitutionBox = [] // inversion of sbox
let rcon: number[] = [] // round constant word array
let mix: MixTable = [] // mix-columns table
let imix: MixTable = [] // inverse mix-columns table
let xtime: XTimeTable = [] // xtime table for GF(2^8) multiplication

export class AESAlgorithm implements Algorithm {
  name: string
  mode!: CipherMode // definite assignment assertion
  _init: boolean
  _w: number[]

  constructor(name: string, mode: (options?: any) => CipherMode) {
    this.name = name
    this._init = false
    this._w = []

    if (!init) {
      initialize()
    }

    this.name = name
    this.mode = mode({
      blockSize: 16,
      cipher: {
        encrypt: (inBlock: number[], outBlock: number[]) => {
          return _updateBlock(this._w, inBlock, outBlock, false)
        },
        decrypt: (inBlock: number[], outBlock: number[]) => {
          return _updateBlock(this._w, inBlock, outBlock, true)
        },
      },
    })
  }

  /**
   * Initializes this AES algorithm by expanding its key.
   *
   * @param options the options to use.
   * @param options.key the key to use with this algorithm.
   * @param options.decrypt `true` if the algorithm should be initialized for decryption, `false` for encryption.
   *
   * Note: The key may be a string of bytes, an array of bytes, a byte
   * buffer, or an array of 32-bit integers. If the key is in bytes, then
   * it must be 16, 24, or 32 bytes in length. If it is in 32-bit
   * integers, it must be 4, 6, or 8 integers long.
   */
  initialize(options: AlgorithmOptions = {}): void {
    if (this._init) {
      return
    }

    let key = options.key
    let tmp: ByteStringBuffer | undefined

    /* Note: The key may be a string of bytes, an array of bytes, a byte
      buffer, or an array of 32-bit integers. If the key is in bytes, then
      it must be 16, 24, or 32 bytes in length. If it is in 32-bit
      integers, it must be 4, 6, or 8 integers long. */

    if (typeof key === 'string' && key.length && (key.length === 16 || key.length === 24 || key.length === 32)) {
      // convert key string into byte buffer
      tmp = createBuffer(key)
      key = tmp
    }
    else if (Array.isArray(key) && (key.length === 16 || key.length === 24 || key.length === 32)) {
      // convert key integer array into byte buffer
      tmp = createBuffer()
      for (let i = 0; i < key.length; ++i) {
        tmp.putByte(key[i])
      }
      key = tmp
    }

    // convert key byte buffer into 32-bit integer array
    let keyInts: number[] = []
    if (key && key instanceof ByteStringBuffer) {
      // key lengths of 16, 24, 32 bytes allowed
      const len = key.length()
      if (len === 16 || len === 24 || len === 32) {
        const numInts = len >>> 2
        for (let i = 0; i < numInts; ++i) {
          keyInts.push(key.getInt32())
        }
      }
    }
    else if (Array.isArray(key)) {
      keyInts = key
    }

    // key must be an array of 32-bit integers by now
    if (!Array.isArray(keyInts) || !(keyInts.length === 4 || keyInts.length === 6 || keyInts.length === 8)) {
      throw new Error('Invalid key parameter.')
    }

    // encryption operation is always used for these modes
    const mode = this.mode.name
    const encryptOp = (['CFB', 'OFB', 'CTR', 'GCM'].includes(mode))

    // do key expansion
    this._w = _expandKey(keyInts, options.decrypt === true && !encryptOp)
    this._init = true
  }
}

/**
 * Expands a key. Typically only used for testing.
 *
 * @param key the symmetric key to expand, as an array of 32-bit words.
 * @param decrypt true to expand for decryption, false for encryption.
 *
 * @return the expanded key.
 */
export function expandKey(key: number[], decrypt: boolean): number[] {
  if (!init) {
    initialize()
  }
  return _expandKey(key, decrypt)
}

/** Register AES algorithms */

export function registerAESAlgorithm(name: string, mode: any): void {
  const factory = function () {
    return new AESAlgorithm(name, mode)
  }

  registerCipherAlgorithm(name, factory)
}

registerAESAlgorithm('AES-ECB', modes.ecb)
registerAESAlgorithm('AES-CBC', modes.cbc)
registerAESAlgorithm('AES-CFB', modes.cfb)
registerAESAlgorithm('AES-OFB', modes.ofb)
registerAESAlgorithm('AES-CTR', modes.ctr)
registerAESAlgorithm('AES-GCM', modes.gcm)

/**
 * Performs initialization, ie: precomputes tables to optimize for speed.
 *
 * One way to understand how AES works is to imagine that 'addition' and
 * 'multiplication' are interfaces that require certain mathematical
 * properties to hold true (ie: they are associative) but they might have
 * different implementations and produce different kinds of results ...
 * provided that their mathematical properties remain true. AES defines
 * its own methods of addition and multiplication but keeps some important
 * properties the same, ie: associativity and distributivity. The
 * explanation below tries to shed some light on how AES defines addition
 * and multiplication of bytes and 32-bit words in order to perform its
 * encryption and decryption algorithms.
 *
 * The basics:
 *
 * The AES algorithm views bytes as binary representations of polynomials
 * that have either 1 or 0 as the coefficients. It defines the addition
 * or subtraction of two bytes as the XOR operation. It also defines the
 * multiplication of two bytes as a finite field referred to as GF(2^8)
 * (Note: 'GF' means "Galois Field" which is a field that contains a finite
 * number of elements so GF(2^8) has 256 elements).
 *
 * This means that any two bytes can be represented as binary polynomials;
 * when they multiplied together and modularly reduced by an irreducible
 * polynomial of the 8th degree, the results are the field GF(2^8). The
 * specific irreducible polynomial that AES uses in hexadecimal is 0x11b.
 * This multiplication is associative with 0x01 as the identity:
 *
 * (b * 0x01 = GF(b, 0x01) = b).
 *
 * The operation GF(b, 0x02) can be performed at the byte level by left
 * shifting b once and then XOR'ing it (to perform the modular reduction)
 * with 0x11b if b is >= 128. Repeated application of the multiplication
 * of 0x02 can be used to implement the multiplication of any two bytes.
 *
 * For instance, multiplying 0x57 and 0x13, denoted as GF(0x57, 0x13), can
 * be performed by factoring 0x13 into 0x01, 0x02, and 0x10. Then these
 * factors can each be multiplied by 0x57 and then added together. To do
 * the multiplication, values for 0x57 multiplied by each of these 3 factors
 * can be precomputed and stored in a table. To add them, the values from
 * the table are XOR'd together.
 *
 * AES also defines addition and multiplication of words, that is 4-byte
 * numbers represented as polynomials of 3 degrees where the coefficients
 * are the values of the bytes.
 *
 * The word [a0, a1, a2, a3] is a polynomial a3x^3 + a2x^2 + a1x + a0.
 *
 * Addition is performed by XOR'ing like powers of x. Multiplication
 * is performed in two steps, the first is an algebriac expansion as
 * you would do normally (where addition is XOR). But the result is
 * a polynomial larger than 3 degrees and thus it cannot fit in a word. So
 * next the result is modularly reduced by an AES-specific polynomial of
 * degree 4 which will always produce a polynomial of less than 4 degrees
 * such that it will fit in a word. In AES, this polynomial is x^4 + 1.
 *
 * The modular product of two polynomials 'a' and 'b' is thus:
 *
 * d(x) = d3x^3 + d2x^2 + d1x + d0
 * with
 * d0 = GF(a0, b0) ^ GF(a3, b1) ^ GF(a2, b2) ^ GF(a1, b3)
 * d1 = GF(a1, b0) ^ GF(a0, b1) ^ GF(a3, b2) ^ GF(a2, b3)
 * d2 = GF(a2, b0) ^ GF(a1, b1) ^ GF(a0, b2) ^ GF(a3, b3)
 * d3 = GF(a3, b0) ^ GF(a2, b1) ^ GF(a1, b2) ^ GF(a0, b3)
 *
 * As a matrix:
 *
 * [d0] = [a0 a3 a2 a1][b0]
 * [d1]   [a1 a0 a3 a2][b1]
 * [d2]   [a2 a1 a0 a3][b2]
 * [d3]   [a3 a2 a1 a0][b3]
 *
 * Special polynomials defined by AES (0x02 == {02}):
 * a(x)    = {03}x^3 + {01}x^2 + {01}x + {02}
 * a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}.
 *
 * These polynomials are used in the MixColumns() and InverseMixColumns()
 * operations, respectively, to cause each element in the state to affect
 * the output (referred to as diffusing).
 *
 * RotWord() uses: a0 = a1 = a2 = {00} and a3 = {01}, which is the
 * polynomial x3.
 *
 * The ShiftRows() method modifies the last 3 rows in the state (where
 * the state is 4 words with 4 bytes per word) by shifting bytes cyclically.
 * The 1st byte in the second row is moved to the end of the row. The 1st
 * and 2nd bytes in the third row are moved to the end of the row. The 1st,
 * 2nd, and 3rd bytes are moved in the fourth row.
 *
 * More details on how AES arithmetic works:
 *
 * In the polynomial representation of binary numbers, XOR performs addition
 * and subtraction and multiplication in GF(2^8) denoted as GF(a, b)
 * corresponds with the multiplication of polynomials modulo an irreducible
 * polynomial of degree 8. In other words, for AES, GF(a, b) will multiply
 * polynomial 'a' with polynomial 'b' and then do a modular reduction by
 * an AES-specific irreducible polynomial of degree 8.
 *
 * A polynomial is irreducible if its only divisors are one and itself. For
 * the AES algorithm, this irreducible polynomial is:
 *
 * m(x) = x^8 + x^4 + x^3 + x + 1,
 *
 * or {01}{1b} in hexadecimal notation, where each coefficient is a bit:
 * 100011011 = 283 = 0x11b.
 *
 * For example, GF(0x57, 0x83) = 0xc1 because
 *
 * 0x57 = 87  = 01010111 = x^6 + x^4 + x^2 + x + 1
 * 0x85 = 131 = 10000101 = x^7 + x + 1
 *
 * (x^6 + x^4 + x^2 + x + 1) * (x^7 + x + 1)
 * =  x^13 + x^11 + x^9 + x^8 + x^7 +
 *    x^7 + x^5 + x^3 + x^2 + x +
 *    x^6 + x^4 + x^2 + x + 1
 * =  x^13 + x^11 + x^9 + x^8 + x^6 + x^5 + x^4 + x^3 + 1 = y
 *    y modulo (x^8 + x^4 + x^3 + x + 1)
 * =  x^7 + x^6 + 1.
 *
 * The modular reduction by m(x) guarantees the result will be a binary
 * polynomial of less than degree 8, so that it can fit in a byte.
 *
 * The operation to multiply a binary polynomial b with x (the polynomial
 * x in binary representation is 00000010) is:
 *
 * b_7x^8 + b_6x^7 + b_5x^6 + b_4x^5 + b_3x^4 + b_2x^3 + b_1x^2 + b_0x^1
 *
 * To get GF(b, x) we must reduce that by m(x). If b_7 is 0 (that is the
 * most significant bit is 0 in b) then the result is already reduced. If
 * it is 1, then we can reduce it by subtracting m(x) via an XOR.
 *
 * It follows that multiplication by x (00000010 or 0x02) can be implemented
 * by performing a left shift followed by a conditional bitwise XOR with
 * 0x1b. This operation on bytes is denoted by xtime(). Multiplication by
 * higher powers of x can be implemented by repeated application of xtime().
 *
 * By adding intermediate results, multiplication by any constant can be
 * implemented. For instance:
 *
 * GF(0x57, 0x13) = 0xfe because:
 *
 * xtime(b) = (b & 128) ? (b << 1 ^ 0x11b) : (b << 1)
 *
 * Note: We XOR with 0x11b instead of 0x1b because in javascript our
 * datatype for b can be larger than 1 byte, so a left shift will not
 * automatically eliminate bits that overflow a byte ... by XOR'ing the
 * overflow bit with 1 (the extra one from 0x11b) we zero it out.
 *
 * GF(0x57, 0x02) = xtime(0x57) = 0xae
 * GF(0x57, 0x04) = xtime(0xae) = 0x47
 * GF(0x57, 0x08) = xtime(0x47) = 0x8e
 * GF(0x57, 0x10) = xtime(0x8e) = 0x07
 *
 * GF(0x57, 0x13) = GF(0x57, (0x01 ^ 0x02 ^ 0x10))
 *
 * And by the distributive property (since XOR is addition and GF() is
 * multiplication):
 *
 * = GF(0x57, 0x01) ^ GF(0x57, 0x02) ^ GF(0x57, 0x10)
 * = 0x57 ^ 0xae ^ 0x07
 * = 0xfe.
 */
function initialize() {
  init = true

  /* Populate the Rcon table. These are the values given by
    [x^(i-1),{00},{00},{00}] where x^(i-1) are powers of x (and x = 0x02)
    in the field of GF(2^8), where i starts at 1.

    rcon[0] = [0x00, 0x00, 0x00, 0x00]
    rcon[1] = [0x01, 0x00, 0x00, 0x00] 2^(1-1) = 2^0 = 1
    rcon[2] = [0x02, 0x00, 0x00, 0x00] 2^(2-1) = 2^1 = 2
    ...
    rcon[9]  = [0x1B, 0x00, 0x00, 0x00] 2^(9-1)  = 2^8 = 0x1B
    rcon[10] = [0x36, 0x00, 0x00, 0x00] 2^(10-1) = 2^9 = 0x36

    We only store the first byte because it is the only one used.
  */
  rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

  // compute xtime table which maps i onto GF(i, 0x02)
  xtime = Array.from({ length: 256 })
  for (let i = 0; i < 128; ++i) {
    xtime[i] = i << 1
    xtime[i + 128] = (i + 128) << 1 ^ 0x11B
  }

  // compute all other tables
  sbox = Array.from({ length: 256 })
  isbox = Array.from({ length: 256 })
  mix = Array.from({ length: 4 })
  imix = Array.from({ length: 4 })
  for (let i = 0; i < 4; ++i) {
    mix[i] = Array.from({ length: 256 }).fill([]).map(() => Array.from({ length: 4 }))
    imix[i] = Array.from({ length: 256 }).fill([]).map(() => Array.from({ length: 4 }))
  }

  let e = 0
  let ei = 0
  let e2: number
  let e4: number
  let e8: number
  let sx: number
  let sx2: number
  let me: number
  let ime: number

  for (let i = 0; i < 256; ++i) {
    sx = ei ^ (ei << 1) ^ (ei << 2) ^ (ei << 3) ^ (ei << 4)
    sx = (sx >> 8) ^ (sx & 255) ^ 0x63

    // update tables
    sbox[e] = sx
    isbox[sx] = e

    // calculate mix table values
    sx2 = xtime[sx]
    e2 = xtime[e]
    e4 = xtime[e2]
    e8 = xtime[e4]

    // Calculate mix and inverse mix values using numeric operations
    const sx2Byte = Number(sx2 & 0xFF)
    const sxByte = Number(sx & 0xFF)
    const sx2sxByte = Number(sx ^ sx2 & 0xFF)

    const e2e4e8Byte = Number(e2 ^ e4 ^ e8 & 0xFF)
    const ee8Byte = Number(e ^ e8 & 0xFF)
    const ee4e8Byte = Number(e ^ e4 ^ e8 & 0xFF)
    const ee2e8Byte = Number(e ^ e2 ^ e8 & 0xFF)

    me = sx2Byte * 0x1000000 + sxByte * 0x10000 + sxByte * 0x100 + sx2sxByte
    ime = e2e4e8Byte * 0x1000000 + ee8Byte * 0x10000 + ee4e8Byte * 0x100 + ee2e8Byte

    // produce each of the mix tables by rotating the 2,1,1,3 value
    for (let n = 0; n < 4; ++n) {
      mix[n][e] = [
        Number((me / 0x1000000) & 0xFF),
        Number((me / 0x10000) & 0xFF),
        Number((me / 0x100) & 0xFF),
        Number(me & 0xFF),
      ]
      imix[n][sx] = [
        Number((ime / 0x1000000) & 0xFF),
        Number((ime / 0x10000) & 0xFF),
        Number((ime / 0x100) & 0xFF),
        Number(ime & 0xFF),
      ]
      // cycle the right most byte to the left most position using numeric operations
      me = Number((me % 0x1000000) * 0x100 + Math.floor(me / 0x1000000))
      ime = Number((ime % 0x1000000) * 0x100 + Math.floor(ime / 0x1000000))
    }

    // get next element and inverse
    if (e === 0) {
      // 1 is the inverse of 1
      e = ei = 1
    }
    else {
      // e = 2e + 2*2*2*(10e)) = multiply e by 82 (chosen generator)
      // ei = ei + 2*2*ei = multiply ei by 5 (inverse generator)
      e = e2 ^ xtime[xtime[xtime[e2 ^ e8]]]
      ei ^= xtime[xtime[ei]]
    }
  }
}

/**
 * Generates a key schedule using the AES key expansion algorithm.
 *
 * The AES algorithm takes the Cipher Key, K, and performs a Key Expansion
 * routine to generate a key schedule. The Key Expansion generates a total
 * of Nb*(Nr + 1) words: the algorithm requires an initial set of Nb words,
 * and each of the Nr rounds requires Nb words of key data. The resulting
 * key schedule consists of a linear array of 4-byte words, denoted [wi ],
 * with i in the range 0 <= i < Nb(Nr + 1).
 *
 * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
 * AES-128 (Nb=4, Nk=4, Nr=10)
 * AES-192 (Nb=4, Nk=6, Nr=12)
 * AES-256 (Nb=4, Nk=8, Nr=14)
 * Note: Nr=Nk+6.
 *
 * Nb is the number of columns (32-bit words) comprising the State (or
 * number of bytes in a block). For AES, Nb=4.
 *
 * @param key the key to schedule (as an array of 32-bit words).
 * @param decrypt true to modify the key schedule to decrypt, false not to.
 *
 * @return the generated key schedule.
 */
export function _expandKey(key: number[], decrypt: boolean): number[] {
  // copy the key's words to initialize the key schedule
  let w = key.slice(0)

  /* RotWord() will rotate a word, moving the first byte to the last
    byte's position (shifting the other bytes left).

    We will be getting the value of Rcon at i / Nk. 'i' will iterate
    from Nk to (Nb * Nr+1). Nk = 4 (4 byte key), Nb = 4 (4 words in
    a block), Nr = Nk + 6 (10). Therefore 'i' will iterate from
    4 to 44 (exclusive). Each time we iterate 4 times, i / Nk will
    increase by 1. We use a counter iNk to keep track of this.
   */

  // go through the rounds expanding the key
  let temp; let iNk = 1
  const Nk = w.length
  const Nr1 = Nk + 6 + 1
  let end = Nb * Nr1
  for (var i = Nk; i < end; ++i) {
    temp = w[i - 1]
    if (i % Nk === 0) {
      // temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk]
      temp
        = sbox[temp >>> 16 & 255] << 24
          ^ sbox[temp >>> 8 & 255] << 16
          ^ sbox[temp & 255] << 8
          ^ sbox[temp >>> 24] ^ (rcon[iNk] << 24)
      iNk++
    }
    else if (Nk > 6 && (i % Nk === 4)) {
      // temp = SubWord(temp)
      temp
        = sbox[temp >>> 24] << 24
          ^ sbox[temp >>> 16 & 255] << 16
          ^ sbox[temp >>> 8 & 255] << 8
          ^ sbox[temp & 255]
    }
    w[i] = w[i - Nk] ^ temp
  }

  /* When we are updating a cipher block we always use the code path for
     encryption whether we are decrypting or not (to shorten code and
     simplify the generation of look up tables). However, because there
     are differences in the decryption algorithm, other than just swapping
     in different look up tables, we must transform our key schedule to
     account for these changes:

     1. The decryption algorithm gets its key rounds in reverse order.
     2. The decryption algorithm adds the round key before mixing columns
       instead of afterwards.

     We don't need to modify our key schedule to handle the first case,
     we can just traverse the key schedule in reverse order when decrypting.

     The second case requires a little work.

     The tables we built for performing rounds will take an input and then
     perform SubBytes() and MixColumns() or, for the decrypt version,
     InvSubBytes() and InvMixColumns(). But the decrypt algorithm requires
     us to AddRoundKey() before InvMixColumns(). This means we'll need to
     apply some transformations to the round key to inverse-mix its columns
     so they'll be correct for moving AddRoundKey() to after the state has
     had its columns inverse-mixed.

     To inverse-mix the columns of the state when we're decrypting we use a
     lookup table that will apply InvSubBytes() and InvMixColumns() at the
     same time. However, the round key's bytes are not inverse-substituted
     in the decryption algorithm. To get around this problem, we can first
     substitute the bytes in the round key so that when we apply the
     transformation via the InvSubBytes()+InvMixColumns() table, it will
     undo our substitution leaving us with the original value that we
     want -- and then inverse-mix that value.

     This change will correctly alter our key schedule so that we can XOR
     each round key with our already transformed decryption state. This
     allows us to use the same code path as the encryption algorithm.

     We make one more change to the decryption key. Since the decryption
     algorithm runs in reverse from the encryption algorithm, we reverse
     the order of the round keys to avoid having to iterate over the key
     schedule backwards when running the encryption algorithm later in
     decryption mode. In addition to reversing the order of the round keys,
     we also swap each round key's 2nd and 4th rows. See the comments
     section where rounds are performed for more details about why this is
     done. These changes are done inline with the other substitution
     described above.
  */
  if (decrypt) {
    let tmp
    const m0 = imix[0]
    const m1 = imix[1]
    const m2 = imix[2]
    const m3 = imix[3]
    const wnew = w.slice(0)
    end = w.length
    for (var i = 0, wi = end - Nb; i < end; i += Nb, wi -= Nb) {
      // do not sub the first or last round key (round keys are Nb
      // words) as no column mixing is performed before they are added,
      // but do change the key order
      if (i === 0 || i === (end - Nb)) {
        wnew[i] = w[wi]
        wnew[i + 1] = w[wi + 3]
        wnew[i + 2] = w[wi + 2]
        wnew[i + 3] = w[wi + 1]
      }
      else {
        // substitute each round key byte because the inverse-mix
        // table will inverse-substitute it (effectively cancel the
        // substitution because round key bytes aren't sub'd in
        // decryption mode) and swap indexes 3 and 1
        for (let n = 0; n < Nb; ++n) {
          tmp = w[wi + n]
          // First, apply sbox substitution to each byte of the word
          // This is done to prepare for the inverse mix operation
          const sboxed = [
            sbox[tmp >>> 24], // Most significant byte
            sbox[(tmp >>> 16) & 255], // Second byte
            sbox[(tmp >>> 8) & 255], // Third byte
            sbox[tmp & 255], // Least significant byte
          ]
          // Then apply the inverse mix operation using the mix tables
          // The Number() conversions ensure proper numeric operations
          // The bitwise OR (|) combines the bytes back into a word
          wnew[i + (3 & -n)] = Number(m0[sboxed[0]])
            | Number(m1[sboxed[1]])
            | Number(m2[sboxed[2]])
            | Number(m3[sboxed[3]])
        }
      }
    }
    w = wnew
  }

  return w
}

/**
 * Updates a single block. Typically only used for testing.
 *
 * @param w the expanded key to use.
 * @param input an array of block-size 32-bit words.
 * @param output an array of block-size 32-bit words.
 * @param decrypt true to decrypt, false to encrypt.
 */
export function _updateBlock(w: number[], input: number[], output: number[], decrypt: boolean): void {
  /* Mixing columns is done using matrix multiplication. The columns
   * that are to be mixed are each a single word in the current state.
   * The state has Nb columns (4 columns). Therefore each column is a
   * 4 byte word. So to mix the columns in a single column 'c' where
   * its rows are r0, r1, r2, and r3, we use the following matrix
   * multiplication:
   *
   * [2 3 1 1]*[r0,c]=[r'0,c]
   * [1 2 3 1] [r1,c] [r'1,c]
   * [1 1 2 3] [r2,c] [r'2,c]
   * [3 1 1 2] [r3,c] [r'3,c]
   *
   * r0, r1, r2, and r3 are each 1 byte of one of the words in the
   * state (a column). To do matrix multiplication for each mixed
   * column c' we multiply the corresponding row from the left matrix
   * with the corresponding column from the right matrix. In total, we
   * get 4 equations:
   *
   * r0,c' = 2*r0,c + 3*r1,c + 1*r2,c + 1*r3,c
   * r1,c' = 1*r0,c + 2*r1,c + 3*r2,c + 1*r3,c
   * r2,c' = 1*r0,c + 1*r1,c + 2*r2,c + 3*r3,c
   * r3,c' = 3*r0,c + 1*r1,c + 1*r2,c + 2*r3,c
   *
   * Therefore to mix the columns in each word in the state we
   * do the following (& 255 omitted for brevity):
   * c'0,r0 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
   * c'0,r1 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
   * c'0,r2 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
   * c'0,r3 = m0[c0 >> 24] ^ m1[c1 >> 16] ^ m2[c2 >> 8] ^ m3[c3]
   *
   * However, before mixing, the algorithm requires us to perform
   * ShiftRows(). The ShiftRows() transformation cyclically shifts the
   * last 3 rows of the state over different offsets. The first row
   * (r = 0) is not shifted.
   *
   * s'_r,c = s_r,(c + shift(r, Nb) mod Nb
   * for 0 < r < 4 and 0 <= c < Nb and
   * shift(1, 4) = 1
   * shift(2, 4) = 2
   * shift(3, 4) = 3.
   *
   * This causes the first byte in r = 1 to be moved to the end of
   * the row, the first 2 bytes in r = 2 to be moved to the end of
   * the row, the first 3 bytes in r = 3 to be moved to the end of
   * the row:
   *
   * r1: [c0 c1 c2 c3] => [c1 c2 c3 c0]
   * r2: [c0 c1 c2 c3]    [c2 c3 c0 c1]
   * r3: [c0 c1 c2 c3]    [c3 c0 c1 c2]
   *
   * We can make these substitutions inline with our column mixing to
   * generate an updated set of equations to produce each word in the
   * state (note the columns have changed positions):
   *
   * c0 c1 c2 c3 => c0 c1 c2 c3
   * c0 c1 c2 c3    c1 c2 c3 c0  (cycled 1 byte)
   * c0 c1 c2 c3    c2 c3 c0 c1  (cycled 2 bytes)
   * c0 c1 c2 c3    c3 c0 c1 c2  (cycled 3 bytes)
   *
   * Therefore:
   *
   * c'0 = 2*r0,c0 + 3*r1,c1 + 1*r2,c2 + 1*r3,c3
   * c'0 = 1*r0,c0 + 2*r1,c1 + 3*r2,c2 + 1*r3,c3
   * c'0 = 1*r0,c0 + 1*r1,c1 + 2*r2,c2 + 3*r3,c3
   * c'0 = 3*r0,c0 + 1*r1,c1 + 1*r2,c2 + 2*r3,c3
   *
   * c'1 = 2*r0,c1 + 3*r1,c2 + 1*r2,c3 + 1*r3,c0
   * c'1 = 1*r0,c1 + 2*r1,c2 + 3*r2,c3 + 1*r3,c0
   * c'1 = 1*r0,c1 + 1*r1,c2 + 2*r2,c3 + 3*r3,c0
   * c'1 = 3*r0,c1 + 1*r1,c2 + 1*r2,c3 + 2*r3,c0
   *
   * ... and so forth for c'2 and c'3. The important distinction is
   * that the columns are cycling, with c0 being used with the m0
   * map when calculating c0, but c1 being used with the m0 map when
   * calculating c1 ... and so forth.
   */

  // Encrypt: AddRoundKey(state, w[0, Nb-1])
  // Decrypt: AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
  const Nr = w.length / 4 - 1
  let m0, m1, m2, m3, sub
  if (decrypt) {
    m0 = imix[0]
    m1 = imix[1]
    m2 = imix[2]
    m3 = imix[3]
    sub = isbox
  }
  else {
    m0 = mix[0]
    m1 = mix[1]
    m2 = mix[2]
    m3 = mix[3]
    sub = sbox
  }
  let a, b, c, d, a2, b2, c2
  a = input[0] ^ w[0]
  b = input[decrypt ? 3 : 1] ^ w[1]
  c = input[2] ^ w[2]
  d = input[decrypt ? 1 : 3] ^ w[3]
  let i = 3

  /* When performing the inverse we transform the mirror image and
   * skip the bottom row, instead of the top one, and move upwards:
   *
   * c3 c2 c1 c0 => c0 c3 c2 c1  (cycled 3 bytes) *same as encryption
   * c3 c2 c1 c0    c1 c0 c3 c2  (cycled 2 bytes)
   * c3 c2 c1 c0    c2 c1 c0 c3  (cycled 1 byte)  *same as encryption
   * c3 c2 c1 c0    c3 c2 c1 c0
   *
   * If you compare the resulting matrices for ShiftRows()+MixColumns()
   * and for InvShiftRows()+InvMixColumns() the 2nd and 4th columns are
   * different (in encrypt mode vs. decrypt mode). So in order to use
   * the same code to handle both encryption and decryption, we will
   * need to do some mapping.
   *
   * If in encryption mode we let a=c0, b=c1, c=c2, d=c3, and r<N> be
   * a row number in the state, then the resulting matrix in encryption
   * mode for applying the above transformations would be:
   *
   * r1: a b c d
   * r2: b c d a
   * r3: c d a b
   * r4: d a b c
   *
   * If we did the same in decryption mode we would get:
   *
   * r1: a d c b
   * r2: b a d c
   * r3: c b a d
   * r4: d c b a
   *
   * If instead we swap d and b (set b=c3 and d=c1), then we get:
   *
   * r1: a b c d
   * r2: d a b c
   * r3: c d a b
   * r4: b c d a
   *
   * Now the 1st and 3rd rows are the same as the encryption matrix. All
   * we need to do then to make the mapping exactly the same is to swap
   * the 2nd and 4th rows when in decryption mode. We also have to do the swap above
   * when we first pull in the input and when we set the final output.
   */

  for (let round = 1; round < Nr; ++round) {
    /* As described above, we'll be using table lookups to perform the
     * column mixing. Each column is stored as a word in the state (the
     * array 'input' has one column as a word at each index). In order to
     * mix a column, we perform these transformations on each row in c,
     * which is 1 byte in each word. The new column for c0 is c'0:
     *
     *        m0      m1      m2      m3
     * r0,c'0 = 2*r0,c0 + 3*r1,c0 + 1*r2,c0 + 1*r3,c0
     * r1,c'0 = 1*r0,c0 + 2*r1,c0 + 3*r2,c0 + 1*r3,c0
     * r2,c'0 = 1*r0,c0 + 1*r1,c0 + 2*r2,c0 + 3*r3,c0
     * r3,c'0 = 3*r0,c0 + 1*r1,c0 + 1*r2,c0 + 2*r3,c0
     *
     * So using mix tables where c0 is a word with r0 being its upper
     * 8 bits and r3 being its lower 8 bits:
     *
     * m0[c0 >> 24] will yield this word: [2*r0,1*r0,1*r0,3*r0]
     * ...
     * m3[c0 & 255] will yield this word: [1*r3,1*r3,3*r3,2*r3]
     */

    // Transform state using the mix tables and key schedule
    a2 = Number(m0[a >>> 24]) // Transform byte 3 using table 0
      | Number(m1[b >>> 16 & 255]) // Transform byte 2 using table 1
      | Number(m2[c >>> 8 & 255]) // Transform byte 1 using table 2
      | Number(m3[d & 255]) ^ w[++i] // Transform byte 0 using table 3

    b2 = Number(m0[b >>> 24])
      | Number(m1[c >>> 16 & 255])
      | Number(m2[d >>> 8 & 255])
      | Number(m3[a & 255]) ^ w[++i]

    c2 = Number(m0[c >>> 24])
      | Number(m1[d >>> 16 & 255])
      | Number(m2[a >>> 8 & 255])
      | Number(m3[b & 255]) ^ w[++i]

    d = Number(m0[d >>> 24])
      | Number(m1[a >>> 16 & 255])
      | Number(m2[b >>> 8 & 255])
      | Number(m3[c & 255]) ^ w[++i]

    // Update state variables for next round
    a = a2
    b = b2
    c = c2

    // cycle the right most byte to the left most position
    // ie: 2,1,1,3 becomes 3,2,1,1
  }

  /*
   * Encrypt:
   * SubBytes(state)
   * ShiftRows(state)
   * AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
   *
   * Decrypt:
   * InvShiftRows(state)
   * InvSubBytes(state)
   * AddRoundKey(state, w[0, Nb-1])
   */
  // Note: rows are shifted inline
  output[0]
    = (sub[a >>> 24] << 24)
      ^ (sub[b >>> 16 & 255] << 16)
      ^ (sub[c >>> 8 & 255] << 8)
      ^ (sub[d & 255]) ^ w[++i]
  output[decrypt ? 3 : 1]
    = (sub[b >>> 24] << 24)
      ^ (sub[c >>> 16 & 255] << 16)
      ^ (sub[d >>> 8 & 255] << 8)
      ^ (sub[a & 255]) ^ w[++i]
  output[2]
    = (sub[c >>> 24] << 24)
      ^ (sub[d >>> 16 & 255] << 16)
      ^ (sub[a >>> 8 & 255] << 8)
      ^ (sub[b & 255]) ^ w[++i]
  output[decrypt ? 1 : 3]
    = (sub[d >>> 24] << 24)
      ^ (sub[a >>> 16 & 255] << 16)
      ^ (sub[b >>> 8 & 255] << 8)
      ^ (sub[c & 255]) ^ w[++i]
}

function createEncryptionCipher(key: string, bits: string | Buffer): BlockCipher {
  return createCipher(key, bits)
}

function createDecryptionCipher(key: string, bits: string | Buffer): BlockCipher {
  return createCipher(key, bits)
}

export interface AES {
  createEncryptionCipher: typeof createEncryptionCipher
  createDecryptionCipher: typeof createDecryptionCipher
  registerAESAlgorithm: typeof registerAESAlgorithm
}

export const aes: AES = {
  createEncryptionCipher,
  createDecryptionCipher,
  registerAESAlgorithm,
}
