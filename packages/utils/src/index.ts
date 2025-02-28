/**
 * Minimal implementation of utilities needed for SHA-1 testing
 */

export class ByteStringBuffer {
  private data: string

  constructor(data = '') {
    this.data = data
  }

  length(): number {
    return this.data.length
  }

  putBytes(bytes: string): ByteStringBuffer {
    this.data += bytes
    return this
  }

  bytes(): string {
    return this.data
  }

  getInt32(): number {
    // Simple mock implementation
    const result = this.data.charCodeAt(0) << 24 |
                  (this.data.length > 1 ? this.data.charCodeAt(1) << 16 : 0) |
                  (this.data.length > 2 ? this.data.charCodeAt(2) << 8 : 0) |
                  (this.data.length > 3 ? this.data.charCodeAt(3) : 0);
    this.data = this.data.substring(4);
    return result;
  }

  compact(): ByteStringBuffer {
    return this
  }

  putInt32(value: number): ByteStringBuffer {
    this.data += String.fromCharCode(
      (value >>> 24) & 0xFF,
      (value >>> 16) & 0xFF,
      (value >>> 8) & 0xFF,
      value & 0xFF
    );
    return this;
  }

  toHex(): string {
    let hex = '';
    for (let i = 0; i < this.data.length; i++) {
      const byte = this.data.charCodeAt(i);
      hex += ((byte & 0xF0) >>> 4).toString(16);
      hex += (byte & 0x0F).toString(16);
    }
    return hex;
  }
}

export function createBuffer(input = ''): ByteStringBuffer {
  return new ByteStringBuffer(input);
}

export function encodeUtf8(str: string): string {
  // Simple implementation for testing
  return str;
}

export function fillString(char: string, length: number): string {
  return char.repeat(length);
}
