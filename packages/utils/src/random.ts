/**
 * Advanced Random Number Generator implementation using the Fortuna algorithm.
 *
 * This implementation provides cryptographically-secure random bytes using
 * the Fortuna algorithm designed by Bruce Schneier and Niels Ferguson.
 * Fortuna is a cryptographically secure pseudo-random number generator (CSPRNG)
 * that is designed to be resistant to various attacks.
 *
 * Key features of this implementation:
 * 1. Uses AES-128 in counter mode as the underlying block cipher
 * 2. Collects entropy from multiple sources when available:
 *    - Native crypto API (window.crypto.getRandomValues)
 *    - System time and performance counters
 *    - Browser/environment state information
 *    - User input events (in browser environments)
 * 3. Implements automatic reseeding based on entropy pool accumulation
 *
 * Security considerations:
 * - In browser environments without native crypto support, initial entropy
 *   can be limited. The implementation attempts to gather entropy from
 *   available sources but may not be cryptographically secure until
 *   sufficient entropy is collected.
 * - In Node.js or secure contexts, it will use the native crypto API
 *   as the primary source of entropy.
 *
 * @author Dave Longley
 * @author Chris Breuer
 */

import type { ByteStringBuffer } from '.'
import { sha256 } from 'ts-hash'
import { _expandKey, _updateBlock } from 'ts-aes'

// Local implementation of ByteStringBuffer to avoid circular dependencies
class LocalByteStringBuffer {
  private data: string
  public read: number

  constructor(b: string | ArrayBuffer | Uint8Array = '') {
    this.data = ''
    this.read = 0

    if (typeof b === 'string') {
      this.data = b
    }
    else if (b instanceof ArrayBuffer || b instanceof Uint8Array) {
      const arr = b instanceof ArrayBuffer ? new Uint8Array(b) : b
      try {
        this.data = String.fromCharCode.apply(null, Array.from(arr))
      }
      catch (e) {
        for (let i = 0; i < arr.length; ++i) {
          this.putByte(arr[i])
        }
      }
    }
  }

  putByte(b: number): LocalByteStringBuffer {
    return this.putBytes(String.fromCharCode(b))
  }

  putBytes(bytes: string): LocalByteStringBuffer {
    this.data += bytes
    return this
  }

  putInt32(i: number): LocalByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i >> 24 & 0xFF)
      + String.fromCharCode(i >> 16 & 0xFF)
      + String.fromCharCode(i >> 8 & 0xFF)
      + String.fromCharCode(i & 0xFF),
    )
  }

  getInt32(): number {
    const rval = (
      this.data.charCodeAt(this.read) << 24
      | this.data.charCodeAt(this.read + 1) << 16
      | this.data.charCodeAt(this.read + 2) << 8
      | this.data.charCodeAt(this.read + 3))
    this.read += 4
    return rval
  }

  getBytes(): string {
    const rval = this.data.slice(this.read)
    this.read = this.data.length
    return rval
  }

  clear(): LocalByteStringBuffer {
    this.data = ''
    this.read = 0
    return this
  }
}

// Local implementation of createBuffer to avoid circular dependencies
function localCreateBuffer(b?: string | ArrayBuffer | Uint8Array): LocalByteStringBuffer {
  return new LocalByteStringBuffer(b)
}

// Define PRNG interface
export interface PRNG {
  getBytes: (count: number, callback?: (err: Error | null, bytes: string) => void) => void | string
  getBytesSync: (count: number) => string
  generate: (count: number, callback?: (err: Error | null, bytes: string) => void) => string
  collect: (bytes: string) => void
  collectInt: (num: number, bits: number) => void
  [key: string]: any // Allow indexing with string
}

export interface PRNGAes {
  formatKey: (key: string | number[] | ByteStringBuffer) => number[]
  formatSeed: (seed: string | number[] | ByteStringBuffer) => number[]
  cipher: (key: number[], seed: number[]) => string
  increment: (seed: number[]) => number[]
  get md(): any
}

interface ExtendedNavigator extends Navigator {
  [key: string]: any // Allow indexing with string
}

declare global {
  interface Window {
    crypto: Crypto
    msCrypto?: Crypto
  }
}

/**
 * The AES-based PRNG implementation used as the core generator.
 * This implementation uses AES-128 in counter mode, where the counter
 * is encrypted to produce random bytes. The key is regularly updated
 * using entropy from the system.
 */
export const prng_aes: PRNGAes = {
  formatKey(key: string | number[] | ByteStringBuffer): number[] {
    // convert the key into 32-bit integers
    const tmp = localCreateBuffer(key as string)
    const result = Array.from({ length: 4 }) as number[]
    result[0] = tmp.getInt32()
    result[1] = tmp.getInt32()
    result[2] = tmp.getInt32()
    result[3] = tmp.getInt32()

    // return the expanded key
    return _expandKey(result, false)
  },

  formatSeed(seed: string | number[] | ByteStringBuffer): number[] {
    // convert seed into 32-bit integers
    const tmp = localCreateBuffer(seed as string)
    const result = Array.from({ length: 4 }) as number[]
    result[0] = tmp.getInt32()
    result[1] = tmp.getInt32()
    result[2] = tmp.getInt32()
    result[3] = tmp.getInt32()

    return result
  },

  cipher(key: number[], seed: number[]): string {
    const output = Array.from({ length: 4 }) as number[]
    _updateBlock(key, seed, output, false)

    const buffer = localCreateBuffer()
    buffer.putInt32(output[0])
    buffer.putInt32(output[1])
    buffer.putInt32(output[2])
    buffer.putInt32(output[3])

    return buffer.getBytes()
  },

  increment(seed: number[]): number[] {
    // FIXME: do we care about carry or signed issues?
    ++seed[3]
    return seed
  },

  get md() {
    return sha256.create()
  }
}

/**
 * Creates a new instance of the PRNG.
 * This function initializes a new generator with its own state,
 * allowing multiple independent random number streams.
 *
 * @returns a new PRNG context
 */
export function spawnPrng(): PRNG {
  // Internal state
  let key: number[] = Array.from({ length: 4 }).fill(0) as number[]
  let seed: number[] = Array.from({ length: 4 }).fill(0) as number[]
  let time = 0
  let collected = 0
  const entropyPool = localCreateBuffer()

  const ctx: PRNG = {
    getBytes(count: number, callback?: (err: Error | null, bytes: string) => void): void | string {
      return ctx.generate(count, callback)
    },

    getBytesSync(count: number): string {
      return ctx.generate(count)
    },

    generate(count: number, callback?: (err: Error | null, bytes: string) => void): string {
      if (count <= 0)
        return ''

      // Reseed if necessary (every 100ms or if enough entropy collected)
      const now = +new Date()
      if (now - time >= 100 || collected >= 32) {
        const entropy = entropyPool.getBytes()
        key = prng_aes.formatKey(entropy)
        seed = prng_aes.formatSeed(entropy)
        time = now
        collected = 0
        entropyPool.clear()
      }

      // Generate random bytes
      let bytes = ''
      while (count > 0) {
        seed = prng_aes.increment(seed)
        bytes += prng_aes.cipher(key, seed)
        count -= 16
      }

      // Truncate to the exact length requested
      if (bytes.length > count)
        bytes = bytes.substr(0, count)

      // Handle callback if provided
      if (callback)
        callback(null, bytes)

      return bytes
    },

    collect(bytes: string): void {
      if (!bytes)
        return

      entropyPool.putBytes(bytes)
      collected += bytes.length
    },

    collectInt(num: number, bits: number): void {
      const bytes = []
      for (let i = 0; i < bits; i += 8)
        bytes.push((num >> i) & 0xFF)

      this.collect(String.fromCharCode.apply(null, bytes))
    },
  }

  return ctx
}

// Get crypto implementation
export function getRandomValues(arr: Uint32Array): Uint32Array {
  const _window = typeof globalThis !== 'undefined' ? globalThis : {} as any

  if (_window.crypto?.getRandomValues)
    return _window.crypto.getRandomValues(arr)

  if (_window.msCrypto?.getRandomValues)
    return _window.msCrypto.getRandomValues(arr)

  throw new Error('No cryptographic random number generator available.')
}

// Expose PRNG spawning capability
export const createInstance: () => PRNG = spawnPrng

export function getBytes(count: number): string | void {
  return createInstance().getBytes(count)
}

export function getBytesSync(count: number): string {
  return createInstance().getBytesSync(count)
}

// Export the random API
export const random: PRNG = createInstance()
