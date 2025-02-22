export * from './hmac'
export * from './pbe'
export * from './pbkdf2'
export * from './random'

/**
 * Constructor for a binary string backed byte buffer.
 *
 * @param [b] the bytes to wrap (either encoded as string, one byte per character, or as an ArrayBuffer or Typed Array).
 */
export class ByteStringBuffer {
  // Class properties
  public data: string
  public read: number
  private _constructedStringLength: number

  constructor(b?: string | ArrayBuffer | ArrayBufferView) {
    // Initialize properties
    this.data = ''
    this.read = 0
    this._constructedStringLength = 0

    if (b !== undefined) {
      if (typeof b === 'string') {
        this.data = b
      }
      else if (isArrayBuffer(b) || isArrayBufferView(b)) {
        if (typeof Buffer !== 'undefined' && b instanceof Buffer) {
          this.data = b.toString('binary')
        }
        else {
          // convert native buffer to forge buffer
          const arr = new Uint8Array(b as ArrayBuffer)
          try {
            this.data = String.fromCharCode(...Array.from(arr))
          }
          catch (e) {
            for (let i = 0; i < arr.length; ++i) {
              this.putByte(arr[i])
            }
          }
        }
      }
      else if (b instanceof ByteStringBuffer) {
        // copy existing buffer
        this.data = b.data
        this.read = b.read
      }
      else if (typeof b === 'object'
        && 'data' in b && typeof b.data === 'string'
        && 'read' in b && typeof b.read === 'number') {
        // copy from object with compatible interface
        this.data = b.data
        this.read = b.read
      }
    }
  }

  /**
   * Gets the number of bytes in this buffer.
   *
   * @return the number of bytes in this buffer.
   */
  length(): number {
    return this.data.length - this.read
  }

  /**
   * Gets whether or not this buffer is empty.
   *
   * @return true if this buffer is empty, false if not.
   */
  isEmpty(): boolean {
    return this.length() <= 0
  }

  /**
   * Puts a byte in this buffer.
   *
   * @param b the byte to put.
   *
   * @return this buffer.
   */
  putByte(b: number): this {
    return this.putBytes(String.fromCharCode(b))
  }

  /**
   * Puts a byte in this buffer N times.
   *
   * @param b the byte to put.
   * @param n the number of bytes of value b to put.
   *
   * @return this buffer.
   */
  fillWithByte(b: number, n: number): this {
    let str = String.fromCharCode(b)
    let d = this.data
    while (n > 0) {
      if (n & 1) {
        d += str
      }
      n >>>= 1
      if (n > 0) {
        str += str
      }
    }
    this.data = d
    this._optimizeConstructedString(n)
    return this
  }

  /**
   * Puts bytes in this buffer.
   *
   * @param bytes the bytes (as a binary encoded string) to put.
   *
   * @return this buffer.
   */
  putBytes(bytes: string): this {
    this.data += bytes
    this._optimizeConstructedString(bytes.length)
    return this
  }

  /**
   * Puts a UTF-16 encoded string into this buffer.
   *
   * @param str the string to put.
   *
   * @return this buffer.
   */
  putString(str: string): this {
    return this.putBytes(encodeUtf8(str))
  }

  /**
   * Puts a 16-bit integer in this buffer in big-endian order.
   *
   * @param i the 16-bit integer.
   *
   * @return this buffer.
   */
  putInt16(i: number): this {
    return this.putBytes(
      String.fromCharCode(i >> 8 & 0xFF)
      + String.fromCharCode(i & 0xFF),
    )
  }

  /**
   * Puts a 24-bit integer in this buffer in big-endian order.
   *
   * @param i the 24-bit integer.
   *
   * @return this buffer.
   */
  putInt24(i: number): this {
    return this.putBytes(
      String.fromCharCode(i >> 16 & 0xFF)
      + String.fromCharCode(i >> 8 & 0xFF)
      + String.fromCharCode(i & 0xFF),
    )
  }

  /**
   * Puts a 32-bit integer in this buffer in big-endian order.
   *
   * @param i the 32-bit integer.
   *
   * @return this buffer.
   */
  putInt32(i: number): this {
    return this.putBytes(
      String.fromCharCode(i >> 24 & 0xFF)
      + String.fromCharCode(i >> 16 & 0xFF)
      + String.fromCharCode(i >> 8 & 0xFF)
      + String.fromCharCode(i & 0xFF),
    )
  }

  /**
   * Puts a 16-bit integer in this buffer in little-endian order.
   *
   * @param i the 16-bit integer.
   *
   * @return this buffer.
   */
  putInt16Le(i: number): this {
    return this.putBytes(
      String.fromCharCode(i & 0xFF)
      + String.fromCharCode(i >> 8 & 0xFF),
    )
  }

  /**
   * Puts a 24-bit integer in this buffer in little-endian order.
   *
   * @param i the 24-bit integer.
   *
   * @return this buffer.
   */
  putInt24Le(i: number): this {
    return this.putBytes(
      String.fromCharCode(i & 0xFF)
      + String.fromCharCode(i >> 8 & 0xFF)
      + String.fromCharCode(i >> 16 & 0xFF),
    )
  }

  /**
   * Puts a 32-bit integer in this buffer in little-endian order.
   *
   * @param i the 32-bit integer.
   *
   * @return this buffer.
   */
  putInt32Le(i: number): this {
    return this.putBytes(
      String.fromCharCode(i & 0xFF)
      + String.fromCharCode(i >> 8 & 0xFF)
      + String.fromCharCode(i >> 16 & 0xFF)
      + String.fromCharCode(i >> 24 & 0xFF),
    )
  }

  /**
   * Puts an n-bit integer in this buffer in big-endian order.
   *
   * @param i the n-bit integer.
   * @param n the number of bits in the integer (8, 16, 24, or 32).
   *
   * @return this buffer.
   */
  putInt(i: number, n: number): this {
    _checkBitsParam(n)
    let bytes = ''
    do {
      n -= 8
      bytes += String.fromCharCode((i >> n) & 0xFF)
    } while (n > 0)
    return this.putBytes(bytes)
  }

  /**
   * Gets a byte from this buffer and advances the read pointer by 1.
   *
   * @return the byte.
   */
  getByte(): number {
    return this.data.charCodeAt(this.read++)
  }

  /**
   * Gets a uint16 from this buffer in big-endian order and advances the read
   * pointer by 2.
   *
   * @return the uint16.
   */
  getInt16(): number {
    const rval = (
      this.data.charCodeAt(this.read) << 8
      ^ this.data.charCodeAt(this.read + 1))
    this.read += 2
    return rval
  }

  /**
   * Gets a uint24 from this buffer in big-endian order and advances the read
   * pointer by 3.
   *
   * @return the uint24.
   */
  getInt24(): number {
    const rval = (
      this.data.charCodeAt(this.read) << 16
      ^ this.data.charCodeAt(this.read + 1) << 8
      ^ this.data.charCodeAt(this.read + 2))
    this.read += 3
    return rval
  }

  /**
   * Gets a uint32 from this buffer in big-endian order and advances the read
   * pointer by 4.
   *
   * @return the word.
   */
  getInt32(): number {
    const rval = (
      this.data.charCodeAt(this.read) << 24
      ^ this.data.charCodeAt(this.read + 1) << 16
      ^ this.data.charCodeAt(this.read + 2) << 8
      ^ this.data.charCodeAt(this.read + 3))
    this.read += 4
    return rval
  }

  /**
   * Gets a uint16 from this buffer in little-endian order and advances the read
   * pointer by 2.
   *
   * @return the uint16.
   */
  getInt16Le(): number {
    const rval = (
      this.data.charCodeAt(this.read)
      ^ this.data.charCodeAt(this.read + 1) << 8)
    this.read += 2
    return rval
  }

  /**
   * Gets a uint24 from this buffer in little-endian order and advances the read
   * pointer by 3.
   *
   * @return the uint24.
   */
  getInt24Le(): number {
    const rval = (
      this.data.charCodeAt(this.read)
      ^ this.data.charCodeAt(this.read + 1) << 8
      ^ this.data.charCodeAt(this.read + 2) << 16)
    this.read += 3
    return rval
  }

  /**
   * Gets a uint32 from this buffer in little-endian order and advances the read
   * pointer by 4.
   *
   * @return the word.
   */
  getInt32Le(): number {
    const rval = (
      this.data.charCodeAt(this.read)
      ^ this.data.charCodeAt(this.read + 1) << 8
      ^ this.data.charCodeAt(this.read + 2) << 16
      ^ this.data.charCodeAt(this.read + 3) << 24)
    this.read += 4
    return rval
  }

  /**
   * Gets an n-bit integer from this buffer in big-endian order and advances the
   * read pointer by n/8.
   *
   * @param n the number of bits in the integer (8, 16, 24, or 32).
   *
   * @return the integer.
   */
  getInt(n: number): number {
    _checkBitsParam(n)
    let rval = 0
    do {
      rval = (rval << 8) + this.data.charCodeAt(this.read++)
      n -= 8
    } while (n > 0)
    return rval
  }

  /**
   * Gets a signed n-bit integer from this buffer in big-endian order, using
   * two's complement, and advances the read pointer by n/8.
   *
   * @param n the number of bits in the integer (8, 16, 24, or 32).
   *
   * @return the integer.
   */
  getSignedInt(n: number): number {
    // getInt checks n
    let x = this.getInt(n)
    const max = 2 << (n - 2)
    if (x >= max) {
      x -= max << 1
    }
    return x
  }

  /**
   * Reads bytes out as a binary encoded string and clears them from the
   * buffer.
   *
   * @param count the number of bytes to read, undefined or null for all.
   *
   * @return a binary encoded string of bytes.
   */
  getBytes(count?: number): string {
    let rval
    if (count) {
      // read count bytes
      count = Math.min(this.length(), count)
      rval = this.data.slice(this.read, this.read + count)
      this.read += count
    }
    else if (count === 0) {
      rval = ''
    }
    else {
      // read all bytes, optimize to only copy when needed
      rval = (this.read === 0) ? this.data : this.data.slice(this.read)
      this.clear()
    }
    return rval
  }

  /**
   * Creates a copy of this buffer.
   *
   * @return the copy.
   */
  copy(): ByteStringBuffer {
    const c = new ByteStringBuffer(this.data)
    c.read = this.read
    return c
  }

  /**
   * Compacts this buffer.
   *
   * @return this buffer.
   */
  compact(): this {
    if (this.read > 0) {
      this.data = this.data.slice(this.read)
      this.read = 0
    }
    return this
  }

  /**
   * Clears this buffer.
   *
   * @return this buffer.
   */
  clear(): this {
    this.data = ''
    this.read = 0
    return this
  }

  /**
   * Shortens this buffer by triming bytes off of the end of this buffer.
   *
   * @param count the number of bytes to trim off.
   *
   * @return this buffer.
   */
  truncate(count: number): this {
    const len = Math.max(0, this.length() - count)
    this.data = this.data.slice(this.read, len)
    this.read = 0
    return this
  }

  /**
   * Converts this buffer to a hexadecimal string.
   *
   * @return a hexadecimal string.
   */
  toHex(): string {
    let rval = ''
    for (let i = this.read; i < this.data.length; ++i) {
      const b = this.data.charCodeAt(i)
      if (b < 16) {
        rval += '0'
      }
      rval += b.toString(16)
    }
    return rval
  }

  /**
   * Converts this buffer to a UTF-16 string (standard JavaScript string).
   *
   * @return a UTF-16 string.
   */
  toString(): string {
    return decodeUtf8(this.bytes())
  }

  // Helper method for string construction optimization
  private _optimizeConstructedString(x: number): void {
    const _MAX_CONSTRUCTED_STRING_LENGTH = 4096
    this._constructedStringLength += x
    if (this._constructedStringLength > _MAX_CONSTRUCTED_STRING_LENGTH) {
      // this substr() should cause the constructed string to join
      this.data.substr(0, 1)
      this._constructedStringLength = 0
    }
  }

  /**
   * Gets a binary encoded string of the bytes from this buffer without
   * modifying the read pointer.
   *
   * @param count the number of bytes to get, omit to get all.
   *
   * @return a string full of binary encoded characters.
   */
  bytes(count?: number): string {
    return (typeof (count) === 'undefined'
      ? this.data.slice(this.read)
      : this.data.slice(this.read, this.read + count))
  }

  /**
   * Gets a byte at the given index without modifying the read pointer.
   *
   * @param i the byte index.
   *
   * @return the byte.
   */
  at(i: number): number {
    return this.data.charCodeAt(this.read + i)
  }

  /**
   * Puts a byte at the given index without modifying the read pointer.
   *
   * @param i the byte index.
   * @param b the byte to put.
   *
   * @return this buffer.
   */
  setAt(i: number, b: number): this {
    this.data = this.data.substr(0, this.read + i)
      + String.fromCharCode(b)
      + this.data.substr(this.read + i + 1)
    return this
  }

  /**
   * Gets the last byte without modifying the read pointer.
   *
   * @return the last byte.
   */
  last(): number {
    return this.data.charCodeAt(this.data.length - 1)
  }

  /**
   * Puts the given buffer into this buffer.
   *
   * @param buffer the buffer to put into this one.
   *
   * @return this buffer.
   */
  putBuffer(buffer: ByteStringBuffer): this {
    return this.putBytes(buffer.getBytes())
  }
}

export const ByteBuffer: typeof ByteStringBuffer = ByteStringBuffer

// Utility functions

/**
 * Creates a buffer that stores bytes.
 *
 * @param [input] a string with encoded bytes to store in the buffer.
 * @param [encoding] (default: 'raw', other: 'utf8').
 */
export function createBuffer(input?: string, encoding?: string): ByteStringBuffer {
  encoding = encoding || 'raw'

  if (input !== undefined && encoding === 'utf8') {
    input = encodeUtf8(input)
  }

  return new ByteStringBuffer(input)
}

/**
 * Checks if the given object is an ArrayBuffer.
 *
 * @param x the object to check.
 *
 * @return true if the object is an ArrayBuffer, false if not.
 */
export function isArrayBuffer(x: any): boolean {
  return typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer
}

/**
 * Checks if the given object is a ArrayBufferView (TypedArray).
 *
 * @param x the object to check.
 *
 * @return true if the object is a ArrayBufferView, false if not.
 */
export function isArrayBufferView(x: any): boolean {
  return x && isArrayBuffer(x.buffer) && x.byteLength !== undefined
}

/**
 * Encodes a string of characters as UTF-8 bytes.
 *
 * @param str the string of characters to encode.
 *
 * @return the UTF-8 bytes.
 */
export function encodeUtf8(str: string): string {
  const encoder = new TextEncoder()
  const bytes = encoder.encode(str)
  return Array.from(bytes).map(b => String.fromCharCode(b)).join('')
}

/**
 * Decodes UTF-8 bytes into a string of characters.
 *
 * @param bytes the UTF-8 bytes to decode.
 *
 * @return the string of characters.
 */
export function decodeUtf8(bytes: string): string {
  return decodeURIComponent(escape(bytes))
}

/**
 * Ensure a bits param is 8, 16, 24, or 32. Used to validate input for
 * algorithms where bit manipulation, JavaScript limitations, and/or algorithm
 * design only allow for byte operations of a limited size.
 *
 * @param n number of bits.
 * @throws Error if n invalid.
 */
export function _checkBitsParam(n: number): void {
  if (!(n === 8 || n === 16 || n === 24 || n === 32)) {
    throw new Error(`Only 8, 16, 24, or 32 bits supported: ${n}`)
  }
}

export const isServer: boolean = !!(typeof process !== 'undefined' && process.versions && (process.versions.node || process.versions.bun))

// 'self' will also work in Web Workers (instance of WorkerGlobalScope) while
// it will point to `window` in the main thread. To remain compatible with
// older browsers, we fall back to 'window' if 'self' is not available.
export const globalScope: typeof globalThis = (function () {
  if (isServer)
    return global

  return typeof self === 'undefined' ? window : self
})()

/**
 * Fills a string with a particular value. If you want the string to be a byte
 * string, pass in String.fromCharCode(theByte).
 *
 * @param c the character to fill the string with, use String.fromCharCode to fill the string with a byte value.
 * @param n the number of characters of value c to fill with.
 *
 * @return the filled string.
 */
export function fillString(c: string, n: number): string {
  let s = ''

  while (n > 0) {
    if (n & 1)
      s += c

    n >>>= 1

    if (n > 0)
      c += c
  }

  return s
}

/**
 * Converts a string of bytes to a hexadecimal string.
 *
 * @param bytes the string of bytes to convert.
 *
 * @return the hexadecimal string.
 */
export function bytesToHex(bytes: string): string {
  return createBuffer(bytes).toHex()
}

// base64 characters, reverse mapping
const _base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
const _base64Idx = [
  /* 43 -43 = 0 */
  /* '+',  1,  2,  3,'/' */
  62,
  -1,
  -1,
  -1,
  63,

  /* '0','1','2','3','4','5','6','7','8','9' */
  52,
  53,
  54,
  55,
  56,
  57,
  58,
  59,
  60,
  61,

  /* 15, 16, 17,'=', 19, 20, 21 */
  -1,
  -1,
  -1,
  64,
  -1,
  -1,
  -1,

  /* 65 - 43 = 22 */
  /* 'A','B','C','D','E','F','G','H','I','J','K','L','M', */
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

  /* 'N','O','P','Q','R','S','T','U','V','W','X','Y','Z' */
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,

  /* 91 - 43 = 48 */
  /* 48, 49, 50, 51, 52, 53 */
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,

  /* 97 - 43 = 54 */
  /* 'a','b','c','d','e','f','g','h','i','j','k','l','m' */
  26,
  27,
  28,
  29,
  30,
  31,
  32,
  33,
  34,
  35,
  36,
  37,
  38,

  /* 'n','o','p','q','r','s','t','u','v','w','x','y','z' */
  39,
  40,
  41,
  42,
  43,
  44,
  45,
  46,
  47,
  48,
  49,
  50,
  51,
]

/**
 * Base64 encodes a 'binary' encoded string of bytes.
 *
 * @param input the binary encoded string of bytes to base64-encode.
 * @param maxline the maximum number of encoded characters per line to use, defaults to none.
 *
 * @return the base64-encoded output.
 */
export function encode64(input: string, maxline?: number): string {
  let line = ''
  let output = ''
  let chr1, chr2, chr3
  let i = 0

  while (i < input.length) {
    chr1 = input.charCodeAt(i++)
    chr2 = input.charCodeAt(i++)
    chr3 = input.charCodeAt(i++)

    // encode 4 character group
    line += _base64.charAt(chr1 >> 2)
    line += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4))
    if (Number.isNaN(chr2)) {
      line += '=='
    }
    else {
      line += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6))
      line += Number.isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63)
    }

    if (maxline && line.length > maxline) {
      output += `${line.substring(0, maxline)}\r\n`
      line = line.substring(maxline)
    }
  }

  output += line

  return output
}

/**
 * Base64 decodes a string into a 'binary' encoded string of bytes.
 *
 * @param input the base64-encoded input.
 *
 * @return the binary encoded string.
 */
export function decode64(input: string): string {
  // TODO: deprecate: "Deprecated. Use util.binary.base64.decode instead."

  // remove all non-base64 characters
  input = input.replace(/[^A-Z0-9+/=]/gi, '')

  let output = ''
  let enc1, enc2, enc3, enc4
  let i = 0

  while (i < input.length) {
    enc1 = _base64Idx[input.charCodeAt(i++) - 43]
    enc2 = _base64Idx[input.charCodeAt(i++) - 43]
    enc3 = _base64Idx[input.charCodeAt(i++) - 43]
    enc4 = _base64Idx[input.charCodeAt(i++) - 43]

    output += String.fromCharCode((enc1 << 2) | (enc2 >> 4))
    if (enc3 !== 64) {
      // decoded at least 2 bytes
      output += String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2))
      if (enc4 !== 64) {
        // decoded 3 bytes
        output += String.fromCharCode(((enc3 & 3) << 6) | enc4)
      }
    }
  }

  return output
}

/**
 * Converts a hex string into a 'binary' encoded string of bytes.
 *
 * @param hex the hexadecimal string to convert.
 *
 * @return the binary-encoded string of bytes.
 */
export function hexToBytes(hex: string): string {
  // TODO: deprecate: "Deprecated. Use util.binary.hex.decode instead."
  let rval = ''
  let i = 0
  if ((hex.length & 1) === 1) {
    // odd number of characters, convert first character alone
    i = 1
    rval += String.fromCharCode(Number.parseInt(hex[0], 16))
  }

  // convert 2 characters (1 byte) at a time
  for (; i < hex.length; i += 2) {
    rval += String.fromCharCode(Number.parseInt(hex.substr(i, 2), 16))
  }

  return rval
}

/**
 * Estimates the number of processes that can be run concurrently. If
 * creating Web Workers, keep in mind that the main JavaScript process needs
 * its own core.
 *
 * @param options the options to use: update true to force an update (not use the cached value).
 * @param callback(err, max) called once the operation completes.
 */
export function estimateCores(options: any, callback: any): void {
  if (typeof options === 'function') {
    callback = options
    options = {}
  }

  options = options || {}

  if ('cores' in util && options?.update !== true)
    return callback(null, util.cores)

  if (typeof navigator !== 'undefined'
    && 'hardwareConcurrency' in navigator
    && navigator.hardwareConcurrency > 0) {
    util.cores = navigator.hardwareConcurrency
    return callback(null, util.cores)
  }

  if (typeof Worker === 'undefined') {
    // workers not available
    util.cores = 1
    return callback(null, util.cores)
  }

  if (typeof Blob === 'undefined') {
    // can't estimate, default to 2
    util.cores = 2
    return callback(null, util.cores)
  }

  // create worker concurrency estimation code as blob
  const blobUrl = URL.createObjectURL(new Blob(['(', function () {
    self.addEventListener('message', (e) => {
      // run worker for 4 ms
      const st = Date.now()
      const et = st + 4
      while (Date.now() < et);
      self.postMessage({ st, et })
    })
  }.toString(), ')()'], { type: 'application/javascript' }))

  // take 5 samples using 16 workers
  sample([], 5, 16)

  function sample(max: number[], samples: number, numWorkers: number) {
    if (samples === 0) {
      // get overlap average
      const avg = Math.floor(max.reduce((acc: number, x: number) => acc + x, 0) / max.length)
      util.cores = Math.max(1, avg)
      URL.revokeObjectURL(blobUrl)
      return callback(null, util.cores)
    }

    map(numWorkers, (err: Error | null, results: any[]) => {
      max.push(reduce(numWorkers, results))
      sample(max, samples - 1, numWorkers)
    })
  }

  function map(numWorkers: number, callback: (err: Error | null, results: any[]) => void) {
    const workers: Worker[] = []
    const results: any[] = []

    for (let i = 0; i < numWorkers; ++i) {
      const worker = new Worker(blobUrl)
      workers.push(worker)
      worker.addEventListener('message', (e: MessageEvent<any>) => {
        results.push(e.data)
        if (results.length === numWorkers) {
          for (let i = 0; i < numWorkers; ++i) {
            workers[i].terminate()
          }
          callback(null, results)
        }
      })
      worker.postMessage(i)
    }
  }

  function reduce(numWorkers: number, results: any[]) {
    // find overlapping time windows
    const overlaps: number[] = []
    for (let n = 0; n < numWorkers; ++n) {
      const r1 = results[n]
      for (let i = 0; i < numWorkers; ++i) {
        if (n === i) {
          continue
        }
        const r2 = results[i]
        if ((r1.st > r2.st && r1.st < r2.et)
          || (r2.st > r1.st && r2.st < r1.et)) {
          overlaps.push(i)
        }
      }
    }
    return overlaps.length
  }
}

/**
 * Performs a per byte XOR between two byte strings and returns the result as a
 * string of bytes.
 *
 * @param s1 first string of bytes.
 * @param s2 second string of bytes.
 * @param n the number of bytes to XOR.
 *
 * @return the XOR'd result.
 */
export function xorBytes(s1: string, s2: string, n: number): string {
  let s3 = ''
  let b = ''
  let t = ''
  let i = 0
  let c = 0

  for (; n > 0; --n, ++i) {
    b = s1.charCodeAt(i) ^ s2.charCodeAt(i)

    if (c >= 10) {
      s3 += t
      t = ''
      c = 0
    }

    t += String.fromCharCode(b)
    ++c
  }

  s3 += t

  return s3
};

export interface Util {
  cores?: number
  isServer: boolean
  globalScope: typeof globalThis
  encode64: typeof encode64
  decode64: typeof decode64
  encodeUtf8: typeof encodeUtf8
  decodeUtf8: typeof decodeUtf8
  isArrayBuffer: typeof isArrayBuffer
  isArrayBufferView: typeof isArrayBufferView
  ByteStringBuffer: typeof ByteStringBuffer
  fillString: typeof fillString
  hexToBytes: typeof hexToBytes
  bytesToHex: typeof bytesToHex
  createBuffer: typeof createBuffer
  _checkBitsParam: typeof _checkBitsParam
  xorBytes: typeof xorBytes
}

export const util: Util = {
  isServer,
  globalScope: (() => {
    if (typeof globalThis !== 'undefined')
      return globalThis
    if (typeof global !== 'undefined')
      return global as unknown as typeof globalThis
    if (typeof self !== 'undefined')
      return (self as unknown) as typeof globalThis
    if (typeof window !== 'undefined')
      return (window as unknown) as typeof globalThis
    return (Object.create(null) as unknown) as typeof globalThis
  })(),
  encode64,
  decode64,
  encodeUtf8,
  decodeUtf8,
  isArrayBuffer,
  isArrayBufferView,
  ByteStringBuffer,
  fillString,
  hexToBytes,
  bytesToHex,
  createBuffer,
  _checkBitsParam,
  xorBytes,
}

export default util

// Add proper type declarations for global objects
declare global {
  var self: WorkerGlobalScope
  var window: Window

  interface Window {
    msCrypto?: {
      subtle: {
        generateKey: Function
        exportKey: Function
      }
    }
    crypto: {
      subtle: {
        generateKey: Function
        exportKey: Function
      }
    }
  }

  interface WorkerGlobalScope {
    msCrypto?: Window['msCrypto']
    crypto: Window['crypto']
    addEventListener(type: 'message', listener: (e: MessageEvent<any>) => void): void
    postMessage(message: any): void
  }

  interface Worker {
    addEventListener(type: 'message', listener: (e: MessageEvent<any>) => void): void
    postMessage(message: any): void
    terminate(): void
  }
}

// Update type checking for crypto availability
function _detectSubtleCrypto(fn: string): boolean {
  return !!(typeof util.globalScope !== 'undefined'
    && typeof util.globalScope.crypto === 'object'
    && typeof util.globalScope.crypto.subtle === 'object'
    && typeof util.globalScope.crypto.subtle[fn as keyof SubtleCrypto] === 'function')
}

function _detectSubtleMsCrypto(fn: string): boolean {
  return !!(typeof util.globalScope !== 'undefined'
    && typeof (util.globalScope as any).msCrypto === 'object'
    && typeof (util.globalScope as any).msCrypto.subtle === 'object'
    && typeof (util.globalScope as any).msCrypto.subtle[fn] === 'function')
}

/**
 * Converts an 32-bit integer to 4-big-endian byte string.
 *
 * @param i the integer.
 *
 * @return the byte string.
 */
export function int32ToBytes(i: number): string {
  return (
    String.fromCharCode(i >> 24 & 0xFF)
    + String.fromCharCode(i >> 16 & 0xFF)
    + String.fromCharCode(i >> 8 & 0xFF)
    + String.fromCharCode(i & 0xFF))
};
