/**
 * ByteStringBuffer implementation for handling binary data.
 *
 * @author Dave Longley
 * @author Chris Breuer
 */

// Define a type for the ByteStringBuffer
export type ByteStringBuffer = {
  data: string;
  read: number;
  _constructedStringLength: number;
  length(): number;
  isEmpty(): boolean;
  putByte(b: number): ByteStringBuffer;
  fillWithByte(b: number, n: number): ByteStringBuffer;
  putBytes(bytes: string): ByteStringBuffer;
  putString(str: string): ByteStringBuffer;
  putInt16(i: number): ByteStringBuffer;
  putInt24(i: number): ByteStringBuffer;
  putInt32(i: number): ByteStringBuffer;
  putInt16Le(i: number): ByteStringBuffer;
  putInt24Le(i: number): ByteStringBuffer;
  putInt32Le(i: number): ByteStringBuffer;
  putInt(i: number, n: number): ByteStringBuffer;
  putSignedInt(i: number, n: number): ByteStringBuffer;
  putBuffer(buffer: ByteStringBuffer): ByteStringBuffer;
  getByte(): number;
  getInt16(): number;
  getInt24(): number;
  getInt32(): number;
  getInt16Le(): number;
  getInt24Le(): number;
  getInt32Le(): number;
  getInt(n: number): number;
  getSignedInt(n: number): number;
  getBytes(count?: number): string;
  bytes(count?: number): string;
  at(i: number): number;
  setAt(i: number, b: number): ByteStringBuffer;
  last(): number;
  copy(): ByteStringBuffer;
  compact(): ByteStringBuffer;
  clear(): ByteStringBuffer;
  truncate(count: number): ByteStringBuffer;
  toHex(): string;
  toString(): string;
  _optimizeConstructedString(n: number): void;
};

/**
 * Creates a byte buffer filled with the given string, buffer, or array.
 *
 * @param b the string, buffer, or array to fill the new buffer with.
 *
 * @return the new buffer.
 */
export function createBuffer(b?: string | ArrayBuffer | Uint8Array): ByteStringBuffer {
  const buffer: ByteStringBuffer = {
    data: '',
    read: 0,
    _constructedStringLength: 0,

    length(): number {
      return this.data.length - this.read;
    },

    isEmpty(): boolean {
      return this.length() <= 0;
    },

    putByte(b: number): ByteStringBuffer {
      this.data += String.fromCharCode(b & 0xFF);
      this._optimizeConstructedString(1);
      return this;
    },

    fillWithByte(b: number, n: number): ByteStringBuffer {
      b &= 0xFF;
      const c = String.fromCharCode(b);
      let added = n;
      while (n > 0) {
        if (n & 1) {
          this.data += c;
        }
        n >>>= 1;
        if (n > 0) {
          this.data += this.data;
        }
      }
      this._optimizeConstructedString(added);
      return this;
    },

    putBytes(bytes: string): ByteStringBuffer {
      this.data += bytes;
      this._optimizeConstructedString(bytes.length);
      return this;
    },

    putString(str: string): ByteStringBuffer {
      return this.putBytes(unescape(encodeURIComponent(str)));
    },

    putInt16(i: number): ByteStringBuffer {
      return this
        .putByte(i >> 8 & 0xFF)
        .putByte(i & 0xFF);
    },

    putInt24(i: number): ByteStringBuffer {
      return this
        .putByte(i >> 16 & 0xFF)
        .putByte(i >> 8 & 0xFF)
        .putByte(i & 0xFF);
    },

    putInt32(i: number): ByteStringBuffer {
      return this
        .putByte(i >> 24 & 0xFF)
        .putByte(i >> 16 & 0xFF)
        .putByte(i >> 8 & 0xFF)
        .putByte(i & 0xFF);
    },

    putInt16Le(i: number): ByteStringBuffer {
      return this
        .putByte(i & 0xFF)
        .putByte(i >> 8 & 0xFF);
    },

    putInt24Le(i: number): ByteStringBuffer {
      return this
        .putByte(i & 0xFF)
        .putByte(i >> 8 & 0xFF)
        .putByte(i >> 16 & 0xFF);
    },

    putInt32Le(i: number): ByteStringBuffer {
      return this
        .putByte(i & 0xFF)
        .putByte(i >> 8 & 0xFF)
        .putByte(i >> 16 & 0xFF)
        .putByte(i >> 24 & 0xFF);
    },

    putInt(i: number, n: number): ByteStringBuffer {
      do {
        n -= 8;
        this.putByte(i >> n & 0xFF);
      } while (n > 0);
      return this;
    },

    putSignedInt(i: number, n: number): ByteStringBuffer {
      if (i < 0) {
        i += 2 ** n;
      }
      return this.putInt(i, n);
    },

    putBuffer(buffer: ByteStringBuffer): ByteStringBuffer {
      return this.putBytes(buffer.getBytes());
    },

    getByte(): number {
      return this.data.charCodeAt(this.read++);
    },

    getInt16(): number {
      const rval = (
        this.data.charCodeAt(this.read) << 8
        ^ this.data.charCodeAt(this.read + 1)
      );
      this.read += 2;
      return rval;
    },

    getInt24(): number {
      const rval = (
        this.data.charCodeAt(this.read) << 16
        ^ this.data.charCodeAt(this.read + 1) << 8
        ^ this.data.charCodeAt(this.read + 2)
      );
      this.read += 3;
      return rval;
    },

    getInt32(): number {
      const rval = (
        this.data.charCodeAt(this.read) << 24
        ^ this.data.charCodeAt(this.read + 1) << 16
        ^ this.data.charCodeAt(this.read + 2) << 8
        ^ this.data.charCodeAt(this.read + 3)
      );
      this.read += 4;
      return rval;
    },

    getInt16Le(): number {
      const rval = (
        this.data.charCodeAt(this.read)
        ^ this.data.charCodeAt(this.read + 1) << 8
      );
      this.read += 2;
      return rval;
    },

    getInt24Le(): number {
      const rval = (
        this.data.charCodeAt(this.read)
        ^ this.data.charCodeAt(this.read + 1) << 8
        ^ this.data.charCodeAt(this.read + 2) << 16
      );
      this.read += 3;
      return rval;
    },

    getInt32Le(): number {
      const rval = (
        this.data.charCodeAt(this.read)
        ^ this.data.charCodeAt(this.read + 1) << 8
        ^ this.data.charCodeAt(this.read + 2) << 16
        ^ this.data.charCodeAt(this.read + 3) << 24
      );
      this.read += 4;
      return rval;
    },

    getInt(n: number): number {
      let rval = 0;
      do {
        rval = (rval << 8) + this.data.charCodeAt(this.read++);
        n -= 8;
      } while (n > 0);
      return rval;
    },

    getSignedInt(n: number): number {
      let x = this.getInt(n);
      const max = 2 ** (n - 1);
      if (x >= max) {
        x -= max * 2;
      }
      return x;
    },

    getBytes(count?: number): string {
      let rval;
      if (count) {
        // read count bytes
        count = Math.min(this.length(), count);
        rval = this.data.slice(this.read, this.read + count);
        this.read += count;
      }
      else if (count === 0) {
        rval = '';
      }
      else {
        // read all bytes, optimize to only copy when needed
        rval = (this.read === 0) ? this.data : this.data.slice(this.read);
        this.clear();
      }
      return rval;
    },

    bytes(count?: number): string {
      return (typeof (count) === 'undefined')
        ? this.data.slice(this.read)
        : this.data.slice(this.read, this.read + count);
    },

    at(i: number): number {
      return this.data.charCodeAt(this.read + i);
    },

    setAt(i: number, b: number): ByteStringBuffer {
      this.data = this.data.substring(0, this.read + i)
        + String.fromCharCode(b)
        + this.data.substring(this.read + i + 1);
      return this;
    },

    last(): number {
      return this.data.charCodeAt(this.data.length - 1);
    },

    copy(): ByteStringBuffer {
      const c = createBuffer();
      c.data = this.data;
      c.read = this.read;
      return c;
    },

    compact(): ByteStringBuffer {
      if (this.read > 0) {
        this.data = this.data.slice(this.read);
        this.read = 0;
      }
      return this;
    },

    clear(): ByteStringBuffer {
      this.data = '';
      this.read = 0;
      return this;
    },

    truncate(count: number): ByteStringBuffer {
      const len = Math.max(0, this.length() - count);
      this.data = this.data.substr(this.read, len);
      this.read = 0;
      return this;
    },

    toHex(): string {
      let rval = '';
      for (let i = this.read; i < this.data.length; ++i) {
        const b = this.data.charCodeAt(i);
        if (b < 16) {
          rval += '0';
        }
        rval += b.toString(16);
      }
      return rval;
    },

    toString(): string {
      return this.data.slice(this.read);
    },

    _optimizeConstructedString(n: number): void {
      this._constructedStringLength += n;
      if (this._constructedStringLength > 1024) {
        this.data = this.data.substr(0, 1) + this.data.substr(1);
        this._constructedStringLength = 0;
      }
    }
  };

  // Initialize with the provided data
  if (b !== undefined) {
    if (typeof b === 'string') {
      buffer.data = b;
    }
    else if (b instanceof ArrayBuffer || b instanceof Uint8Array) {
      const arr = b instanceof ArrayBuffer ? new Uint8Array(b) : b;
      try {
        buffer.data = String.fromCharCode.apply(null, Array.from(arr));
      }
      catch (e) {
        for (let i = 0; i < arr.length; ++i) {
          buffer.putByte(arr[i]);
        }
      }
    }
  }

  return buffer;
}
