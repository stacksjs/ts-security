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

  constructor(b?: string | ArrayBuffer | ArrayBufferView, encoding?: 'utf8' | 'binary') {
    // Initialize properties
    this.data = ''
    this.read = 0
    this._constructedStringLength = 0

    if (b !== undefined) {
      if (typeof b === 'string') {
        if (encoding === 'utf8') {
          const encoder = new TextEncoder()
          const uint8Array = encoder.encode(b)
          this.data = String.fromCharCode(...uint8Array)
        }
        else if (encoding === 'binary') {
          this.data = b
        }
      }
      else if (isArrayBuffer(b) || isArrayBufferView(b)) {
        const view = new Uint8Array(b instanceof ArrayBuffer ? b : b.buffer)
        this.data = String.fromCharCode(...view)
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
    this._constructedStringLength = this.data.length
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

// Create an alias for ByteStringBuffer for backward compatibility
export const ByteBuffer: typeof ByteStringBuffer = ByteStringBuffer

/**
 * Creates a new byte buffer.
 *
 * @param [input] the input to create the byte buffer from.
 * @param [encoding] optional encoding ('utf8' or 'binary').
 *
 * @return the byte buffer.
 */
export function createBuffer(input?: string, encoding?: string): ByteStringBuffer {
  if (input !== undefined && encoding === 'utf8') {
    input = encodeUtf8(input)
  }

  return new ByteStringBuffer(input)
}

// Utility functions

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
  let t = ''
  let b = 0
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

/**
 * Converts an IPv4 or IPv6 string representation into bytes (in network order).
 *
 * @param ip the IPv4 or IPv6 address to convert.
 *
 * @return the 4-byte IPv6 or 16-byte IPv6 address or null if the address can't
 *         be parsed.
 */
export function bytesFromIP(ip: string): string | null {
  if (ip.includes('.'))
    return bytesFromIPv4(ip)

  if (ip.includes(':'))
    return bytesFromIPv6(ip)

  return null
}

/**
 * Converts an IPv4 string representation into bytes (in network order).
 *
 * @param ip the IPv4 address to convert.
 *
 * @return the 4-byte address or null if the address can't be parsed.
 */
export function bytesFromIPv4(ip: string): string | null {
  const ipParts = ip.split('.')

  if (ipParts.length !== 4)
    return null

  const b = createBuffer()

  for (let i = 0; i < ipParts.length; ++i) {
    const num = Number.parseInt(ipParts[i], 10)

    if (Number.isNaN(num))
      return null

    b.putByte(num)
  }

  return b.getBytes()
};

/**
 * Converts an IPv6 string representation into bytes (in network order).
 *
 * @param ip the IPv6 address to convert.
 *
 * @return the 16-byte address or null if the address can't be parsed.
 */
export function bytesFromIPv6(ip: string): string | null {
  let blanks = 0
  const ipParts = ip.split(':').filter((e) => {
    if (e.length === 0)
      ++blanks
    return true
  })

  let zeros = (8 - ipParts.length + blanks) * 2
  const b = createBuffer()

  for (let i = 0; i < 8; ++i) {
    if (!ipParts[i] || ipParts[i].length === 0) {
      b.fillWithByte(0, zeros)
      zeros = 0
      continue
    }
    const bytes = hexToBytes(ipParts[i])
    if (bytes.length < 2)
      b.putByte(0)
    b.putBytes(bytes)
  }

  return b.getBytes()
};

/**
 * Converts 4-bytes into an IPv4 string representation. The bytes must be
 * in network order.
 *
 * @param bytes the bytes to convert.
 *
 * @return the IPv4 string representation or null for an invalid # of bytes.
 */
export function bytesToIPv4(bytes: string): string | null {
  if (bytes.length !== 4)
    return null

  const ip: number[] = []
  for (let i = 0; i < bytes.length; ++i) {
    ip.push(bytes.charCodeAt(i))
  }

  return ip.join('.')
};

/**
 * Converts 4-bytes into an IPv4 string representation or 16-bytes into
 * an IPv6 string representation. The bytes must be in network order.
 *
 * @param bytes the bytes to convert.
 *
 * @return the IPv4 or IPv6 string representation if 4 or 16 bytes, respectively, are given, otherwise null.
 */
export function bytesToIP(bytes: string): string | null {
  if (bytes.length === 4)
    return bytesToIPv4(bytes)

  if (bytes.length === 16)
    return bytesToIPv6(bytes)

  return null
};

/**
 * Converts 16-bytes into an IPv16 string representation. The bytes must be
 * in network order.
 *
 * @param bytes the bytes to convert.
 *
 * @return the IPv16 string representation or null for an invalid # of bytes.
 */
export function bytesToIPv6(bytes: string): string | null {
  if (bytes.length !== 16)
    return null

  const ip: string[] = []
  const zeroGroups: { start: number, end: number }[] = []
  let zeroMaxGroup = 0

  for (let i = 0; i < bytes.length; i += 2) {
    let hex = bytesToHex(bytes[i] + bytes[i + 1])
    // canonicalize zero representation
    while (hex[0] === '0' && hex !== '0') {
      hex = hex.substr(1)
    }
    if (hex === '0') {
      const last = zeroGroups[zeroGroups.length - 1]
      const idx = ip.length
      if (!last || idx !== last.end + 1) {
        zeroGroups.push({ start: idx, end: idx })
      }
      else {
        last.end = idx
        if ((last.end - last.start)
          > (zeroGroups[zeroMaxGroup].end - zeroGroups[zeroMaxGroup].start)) {
          zeroMaxGroup = zeroGroups.length - 1
        }
      }
    }
    ip.push(hex)
  }
  if (zeroGroups.length > 0) {
    const group = zeroGroups[zeroMaxGroup]
    // only shorten group of length > 0
    if (group.end - group.start > 0) {
      ip.splice(group.start, group.end - group.start + 1, '')
      if (group.start === 0) {
        ip.unshift('')
      }
      if (group.end === 7) {
        ip.push('')
      }
    }
  }

  return ip.join(':')
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
  ByteBuffer: typeof ByteBuffer
  bytesToIP: typeof bytesToIP
  bytesToIPv4: typeof bytesToIPv4
  bytesToIPv6: typeof bytesToIPv6
  int32ToBytes: typeof int32ToBytes
  bytesFromIP: typeof bytesFromIP
  bytesFromIPv4: typeof bytesFromIPv4
  bytesFromIPv6: typeof bytesFromIPv6
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
  ByteBuffer,
  bytesToIP,
  bytesToIPv4,
  bytesToIPv6,
  int32ToBytes,
  bytesFromIP,
  bytesFromIPv4,
  bytesFromIPv6,
}

export default util

// Add proper type declarations for global objects
declare global {
  // @ts-expect-error unsure how to better handle this
  var self: WorkerGlobalScope
  // @ts-expect-error unsure how to better handle this
  var window: Window

  interface Window {
    // @ts-expect-error unsure how to better handle this
    msCrypto?: {
      subtle: {
        generateKey: Function
        exportKey: Function
      }
    }
    // @ts-expect-error unsure how to better handle this
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
