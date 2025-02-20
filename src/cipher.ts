/**
 * Cipher base API.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */

import type { ByteStringBuffer } from './utils'
import { createBuffer } from './utils'

export interface AlgorithmMode {
  name?: string
  blockSize: number
  decrypt: (input: any, output: any, finish: boolean) => boolean
  encrypt: (input: any, output: any, finish: boolean) => boolean
  start: (options: CipherOptions) => void
  pad?: (input: any, options: CipherOptions) => boolean
  unpad?: (output: any, options: CipherOptions) => boolean
  afterFinish?: (output: any, options: CipherOptions) => boolean
}

export interface Algorithm {
  mode: AlgorithmMode
  initialize: (options: CipherOptions) => void
}

type AlgorithmFactory = () => Algorithm

const algorithms: Record<string, AlgorithmFactory> = {}

/**
 * Creates a cipher object that can be used to encrypt data using the given
 * algorithm and key. The algorithm may be provided as a string value for a
 * previously registered algorithm or it may be given as a cipher algorithm
 * API object.
 *
 * @param algorithm the algorithm to use, either a string or an algorithm API object.
 * @param key the key to use, as a binary-encoded string of bytes or a byte buffer.
 *
 * @return the cipher.
 */
export function createCipher(algorithm: string | Algorithm, key: string | Buffer): BlockCipher {
  let api: Algorithm | null = typeof algorithm === 'string' ? null : algorithm

  if (typeof algorithm === 'string') {
    const factory = getAlgorithm(algorithm)
    if (factory) {
      api = factory()
    }
  }

  if (!api) {
    throw new Error(`Unsupported algorithm: ${algorithm}`)
  }

  return new BlockCipher({
    algorithm: api,
    key,
    decrypt: false,
  })
}

/**
 * Creates a decipher object that can be used to decrypt data using the given
 * algorithm and key. The algorithm may be provided as a string value for a
 * previously registered algorithm or it may be given as a cipher algorithm
 * API object.
 *
 * @param algorithm the algorithm to use, either a string or an algorithm API object.
 * @param key the key to use, as a binary-encoded string of bytes or a byte buffer.
 *
 * @return the cipher.
 */
export function createDecipher(algorithm: string | Algorithm, key: string | Buffer): BlockCipher {
  let api: Algorithm | null = typeof algorithm === 'string' ? null : algorithm

  if (typeof algorithm === 'string') {
    const factory = getAlgorithm(algorithm)
    if (factory) {
      api = factory()
    }
  }

  if (!api) {
    throw new Error(`Unsupported algorithm: ${algorithm}`)
  }

  return new BlockCipher({
    algorithm: api,
    key,
    decrypt: true,
  })
}

/**
 * Registers an algorithm by name. If the name was already registered, the
 * algorithm API object will be overwritten.
 *
 * @param name the name of the algorithm.
 * @param algorithm the algorithm API object.
 */
export function registerAlgorithm(name: string, algorithm: AlgorithmFactory): void {
  name = name.toUpperCase()
  algorithms[name] = algorithm
}

/**
 * Gets a registered algorithm by name.
 *
 * @param name the name of the algorithm.
 *
 * @return the algorithm, if found, null if not.
 */
export function getAlgorithm(name: string): AlgorithmFactory | null {
  name = name.toUpperCase()

  if (name in algorithms)
    return algorithms[name]

  return null
}

export interface CipherOptions {
  algorithm: Algorithm
  key: any
  decrypt: boolean
  iv?: string | number[] | ByteStringBuffer | null
  additionalData?: string
  tagLength?: number
  tag?: string
  output?: any
  overflow?: number
}

export class BlockCipher {
  private algorithm: Algorithm
  private mode: AlgorithmMode
  private blockSize: number
  private _finish: boolean
  private _input: any
  private output: any
  private _op: (input: any, output: any, finish: boolean) => boolean
  private _decrypt: boolean

  constructor(options: CipherOptions) {
    this.algorithm = options.algorithm
    this.mode = this.algorithm.mode
    this.blockSize = this.mode.blockSize
    this._finish = false
    this._input = null
    this.output = null
    this._op = options.decrypt ? this.mode.decrypt : this.mode.encrypt
    this._decrypt = options.decrypt
    this.algorithm.initialize(options)
  }

  /**
   * Starts or restarts the encryption or decryption process, whichever
   * was previously configured.
   *
   * For non-GCM mode, the IV may be a binary-encoded string of bytes, an array
   * of bytes, a byte buffer, or an array of 32-bit integers. If the IV is in
   * bytes, then it must be Nb (16) bytes in length. If the IV is given in as
   * 32-bit integers, then it must be 4 integers long.
   *
   * Note: an IV is not required or used in ECB mode.
   *
   * For GCM-mode, the IV must be given as a binary-encoded string of bytes or
   * a byte buffer. The number of bytes should be 12 (96 bits) as recommended
   * by NIST SP-800-38D but another length may be given.
   *
   * @param options the options to use:
   *          iv the initialization vector to use as a binary-encoded string of
   *            bytes, null to reuse the last ciphered block from a previous
   *            update() (this "residue" method is for legacy support only).
   *          additionalData additional authentication data as a binary-encoded
   *            string of bytes, for 'GCM' mode, (default: none).
   *          tagLength desired length of authentication tag, in bits, for
   *            'GCM' mode (0-128, default: 128).
   *          tag the authentication tag to check if decrypting, as a
   *             binary-encoded string of bytes.
   *          output the output the buffer to write to, null to create one.
   */
  start(options: Partial<CipherOptions> = {}): void {
    const opts: CipherOptions = {
      ...options,
      decrypt: this._decrypt,
    } as CipherOptions

    this._finish = false
    this._input = createBuffer()
    this.output = options.output || createBuffer()
    this.mode.start(opts)
  }

  /**
   * Updates the next block according to the cipher mode.
   *
   * @param input the buffer to read from.
   */
  update(input?: any): void {
    if (input) {
      // input given, so empty it into the input buffer
      this._input.putBuffer(input)
    }

    // do cipher operation until it needs more input and not finished
    while (!this._op.call(this.mode, this._input, this.output, this._finish)
      && !this._finish) { }

    // free consumed memory from input buffer
    this._input.compact()
  }

  /**
   * Finishes encrypting or decrypting.
   *
   * @param pad a padding function to use in CBC mode, null for default,
   *          signature(blockSize, buffer, decrypt).
   *
   * @return true if successful, false on error.
   */
  finish(pad?: (blockSize: number, buffer: any, decrypt: boolean) => boolean): boolean {
    // backwards-compatibility w/deprecated padding API
    // Note: will overwrite padding functions even after another start() call
    if (pad && (this.mode.name === 'ECB' || this.mode.name === 'CBC')) {
      this.mode.pad = (input: any): boolean => {
        return pad(this.blockSize, input, false)
      }
      this.mode.unpad = (output: any): boolean => {
        return pad(this.blockSize, output, true)
      }
    }

    // build options for padding and afterFinish functions
    const options: CipherOptions = {
      decrypt: this._decrypt,
      algorithm: this.algorithm,
      key: null, // Not needed for finish operation
    }

    // get # of bytes that won't fill a block
    options.overflow = this._input.length() % this.blockSize

    if (!this._decrypt && this.mode.pad) {
      if (!this.mode.pad(this._input, options)) {
        return false
      }
    }

    // do final update
    this._finish = true
    this.update()

    if (this._decrypt && this.mode.unpad) {
      if (!this.mode.unpad(this.output, options)) {
        return false
      }
    }

    if (this.mode.afterFinish) {
      if (!this.mode.afterFinish(this.output, options)) {
        return false
      }
    }

    return true
  }
}
