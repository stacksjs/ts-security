import { expect, it, describe } from 'bun:test'
import { base, ALPHABETS, base64, base58, base32, base16, base2 } from '../src'

describe('ts-base-x', () => {
  describe('base function configuration', () => {
    it('should create a base converter with default BASE58 alphabet', () => {
      const converter = base()
      const input = new Uint8Array([72, 101, 108, 108, 111]) // "Hello"
      const encoded = converter.encode(input)
      const decoded = converter.decode(encoded)
      expect(decoded).toEqual(input)
    })

    it('should throw error for alphabet too long', () => {
      const longAlphabet = 'x'.repeat(255)
      expect(() => base(longAlphabet)).toThrow('Alphabet too long')
    })

    it('should throw error for ambiguous alphabet', () => {
      expect(() => base('00123')).toThrow('0 is ambiguous')
    })
  })

  describe('encoding', () => {
    it('should encode Uint8Array input', () => {
      const input = new Uint8Array([1, 2, 3])
      const encoded = base64.encode(input)
      expect(typeof encoded).toBe('string')
      expect(encoded).toBe('QID')
    })

    it('should handle empty input', () => {
      const input = new Uint8Array(0)
      const encoded = base64.encode(input)
      expect(encoded).toBe('')
    })

    it('should handle leading zeros', () => {
      const input = new Uint8Array([0, 0, 1])
      const encoded = base58.encode(input)
      expect(encoded.startsWith('11')).toBe(true)
    })
  })

  describe('decoding', () => {
    it('should decode valid base64 string', () => {
      const input = 'QID'
      const decoded = base64.decode(input)
      expect(decoded).toEqual(new Uint8Array([1, 2, 3]))
    })

    it('should handle empty string', () => {
      const input = ''
      const decoded = base64.decode(input)
      expect(decoded).toEqual(new Uint8Array(0))
    })

    it('should throw error for invalid characters', () => {
      expect(() => base58.decode('invalid!')).toThrow('Non-base58 character')
    })
  })

  describe('different bases', () => {
    it('should work with base16 (hex)', () => {
      const input = new Uint8Array([255, 0, 128])
      const encoded = base16.encode(input)
      expect(encoded).toBe('ff0080')
      expect(base16.decode(encoded)).toEqual(input)
    })

    it('should work with base2 (binary)', () => {
      const input = new Uint8Array([5]) // 00000101 in binary
      const encoded = base2.encode(input)
      expect(encoded).toBe('101')
      expect(base2.decode(encoded)).toEqual(input)
    })

    it('should work with base32', () => {
      const input = new Uint8Array([72, 101, 108, 108, 111]) // "Hello"
      const encoded = base32.encode(input)
      const decoded = base32.decode(encoded)
      expect(decoded).toEqual(input)
    })
  })

  describe('error handling', () => {
    it('should throw for invalid input types in encode', () => {
      expect(() => base64.encode('not a Uint8Array' as any)).toThrow('Expected Uint8Array')
    })

    it('should throw for invalid input types in decode', () => {
      expect(() => base64.decode(123 as any)).toThrow('Expected String')
    })

    it('should throw for invalid characters', () => {
      // The implementation uses 'Non-base58 character' for all bases
      expect(() => base58.decode('invalid!')).toThrow('Non-base58 character')
      expect(() => base16.decode('0123456789abcdefg')).toThrow('Non-base58 character')
      expect(() => base2.decode('1012')).toThrow('Non-base58 character')
    })
  })

  describe('roundtrip tests', () => {
    const testCases = [
      new Uint8Array([]),
      new Uint8Array([0]),
      new Uint8Array([1, 2, 3, 4, 5]),
      new Uint8Array([0, 0, 0, 0, 1]),
      new Uint8Array([255, 255, 255]),
      new Uint8Array(Array(100).fill(65)), // Longer input
    ]

    for (const testCase of testCases) {
      it(`should correctly roundtrip ${testCase.length} bytes`, () => {
        const encoded = base64.encode(testCase)
        const decoded = base64.decode(encoded)
        expect(decoded).toEqual(testCase)
      })
    }
  })
})
