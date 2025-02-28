/**
 * Minimal implementation of utilities needed for SHA-1 testing
 */

export class ByteStringBuffer {
  private data: string
  private read: number
  private _constructedStringLength: number

  constructor(b: string | ArrayBuffer | Uint8Array = '') {
    this.data = ''
    this.read = 0
    this._constructedStringLength = 0

    if (typeof b === 'string') {
      this.data = b
    } else if (b instanceof ArrayBuffer || b instanceof Uint8Array) {
      const arr = b instanceof ArrayBuffer ? new Uint8Array(b) : b
      try {
        this.data = String.fromCharCode.apply(null, Array.from(arr))
      } catch (e) {
        for (let i = 0; i < arr.length; ++i) {
          this.putByte(arr[i])
        }
      }
    }
  }

  length(): number {
    return this.data.length - this.read
  }

  isEmpty(): boolean {
    return this.length() <= 0
  }

  putByte(b: number): ByteStringBuffer {
    return this.putBytes(String.fromCharCode(b))
  }

  fillWithByte(b: number, n: number): ByteStringBuffer {
    let d = this.data
    const char = String.fromCharCode(b)
    while (n > 0) {
      if (n & 1) {
        d += char
      }
      n >>>= 1
      if (n > 0) {
        d += d
      }
    }
    this.data = d
    this._optimizeConstructedString(1)
    return this
  }

  putBytes(bytes: string): ByteStringBuffer {
    this.data += bytes
    this._optimizeConstructedString(bytes.length)
    return this
  }

  putString(str: string): ByteStringBuffer {
    return this.putBytes(encodeUtf8(str))
  }

  putInt16(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i & 0xFF))
  }

  putInt24(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i >> 16 & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i & 0xFF))
  }

  putInt32(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i >> 24 & 0xFF) +
      String.fromCharCode(i >> 16 & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i & 0xFF))
  }

  putInt16Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF))
  }

  putInt24Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i >> 16 & 0xFF))
  }

  putInt32Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i >> 16 & 0xFF) +
      String.fromCharCode(i >> 24 & 0xFF))
  }

  putInt(i: number, n: number): ByteStringBuffer {
    _checkBitsParam(n)
    let bytes = ''
    do {
      n -= 8
      bytes += String.fromCharCode((i >> n) & 0xFF)
    } while (n > 0)
    return this.putBytes(bytes)
  }

  putSignedInt(i: number, n: number): ByteStringBuffer {
    if (i < 0) {
      i += 2 << (n - 1)
    }
    return this.putInt(i, n)
  }

  putBuffer(buffer: ByteStringBuffer): ByteStringBuffer {
    return this.putBytes(buffer.getBytes())
  }

  getByte(): number {
    return this.data.charCodeAt(this.read++)
  }

  getInt16(): number {
    const rval = (
      this.data.charCodeAt(this.read) << 8 |
      this.data.charCodeAt(this.read + 1))
    this.read += 2
    return rval
  }

  getInt24(): number {
    const rval = (
      this.data.charCodeAt(this.read) << 16 |
      this.data.charCodeAt(this.read + 1) << 8 |
      this.data.charCodeAt(this.read + 2))
    this.read += 3
    return rval
  }

  getInt32(): number {
    const rval = (
      this.data.charCodeAt(this.read) << 24 |
      this.data.charCodeAt(this.read + 1) << 16 |
      this.data.charCodeAt(this.read + 2) << 8 |
      this.data.charCodeAt(this.read + 3))
    this.read += 4
    return rval
  }

  getInt16Le(): number {
    const rval = (
      this.data.charCodeAt(this.read) |
      this.data.charCodeAt(this.read + 1) << 8)
    this.read += 2
    return rval
  }

  getInt24Le(): number {
    const rval = (
      this.data.charCodeAt(this.read) |
      this.data.charCodeAt(this.read + 1) << 8 |
      this.data.charCodeAt(this.read + 2) << 16)
    this.read += 3
    return rval
  }

  getInt32Le(): number {
    const rval = (
      this.data.charCodeAt(this.read) |
      this.data.charCodeAt(this.read + 1) << 8 |
      this.data.charCodeAt(this.read + 2) << 16 |
      this.data.charCodeAt(this.read + 3) << 24)
    this.read += 4
    return rval
  }

  getInt(n: number): number {
    _checkBitsParam(n)
    let rval = 0
    do {
      rval = (rval << 8) | this.data.charCodeAt(this.read++)
      n -= 8
    } while (n > 0)
    return rval
  }

  getSignedInt(n: number): number {
    let x = this.getInt(n)
    const max = 2 << (n - 2)
    if (x >= max) {
      x -= max << 1
    }
    return x
  }

  getBytes(count?: number): string {
    let rval
    if (count) {
      count = Math.min(this.length(), count)
      rval = this.data.slice(this.read, this.read + count)
      this.read += count
    } else if (count === 0) {
      rval = ''
    } else {
      rval = (this.read === 0) ? this.data : this.data.slice(this.read)
      this.clear()
    }
    return rval
  }

  bytes(count?: number): string {
    return (typeof(count) === 'undefined' ?
      this.data.slice(this.read) :
      this.data.slice(this.read, this.read + count))
  }

  at(i: number): number {
    return this.data.charCodeAt(this.read + i)
  }

  setAt(i: number, b: number): ByteStringBuffer {
    this.data = this.data.substr(0, this.read + i) +
      String.fromCharCode(b) +
      this.data.substr(this.read + i + 1)
    return this
  }

  last(): number {
    return this.data.charCodeAt(this.data.length - 1)
  }

  copy(): ByteStringBuffer {
    const c = createBuffer(this.data)
    c.read = this.read
    return c
  }

  compact(): ByteStringBuffer {
    if (this.read > 0) {
      this.data = this.data.slice(this.read)
      this.read = 0
    }
    return this
  }

  clear(): ByteStringBuffer {
    this.data = ''
    this.read = 0
    return this
  }

  truncate(count: number): ByteStringBuffer {
    const len = Math.max(0, this.length() - count)
    this.data = this.data.substr(this.read, len)
    this.read = 0
    return this
  }

  toHex(): string {
    const s = this.data.slice(this.read)
    let rval = ''
    for (let i = 0; i < s.length; ++i) {
      const b = s.charCodeAt(i)
      rval += (b < 16 ? '0' : '') + b.toString(16)
    }
    return rval
  }

  toString(): string {
    return this.data.slice(this.read)
  }

  private _optimizeConstructedString(n: number): void {
    this._constructedStringLength += n
    if (this._constructedStringLength > 1024) {
      this.data = this.data.substr(0, 1) + this.data.substr(1)
      this._constructedStringLength = 0
    }
  }
}

export function createBuffer(b?: string | ArrayBuffer | Uint8Array): ByteStringBuffer {
  return new ByteStringBuffer(b)
}

export function fillString(char: string, count: number): string {
  let s = ''
  while (count > 0) {
    if (count & 1) {
      s += char
    }
    count >>>= 1
    if (count > 0) {
      char += char
    }
  }
  return s
}

export function encodeUtf8(str: string): string {
  return unescape(encodeURIComponent(str))
}

function _checkBitsParam(n: number): void {
  if (!(n <= 32 && n > 0 && n % 8 === 0)) {
    throw new Error('Number of bits must be 8, 16, 24, or 32')
  }
}
