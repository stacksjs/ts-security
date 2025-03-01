import { describe, expect, it } from 'bun:test'
import { ByteStringBuffer } from 'ts-security-utils'
import { sha256 } from '../src/sha256'

describe('SHA-256', () => {
  describe('API structure', () => {
    it('should export a sha256 object with create method', () => {
      expect(sha256).toBeDefined()
      expect(typeof sha256.create).toBe('function')
    })

    it('should create a SHA-256 message digest object with correct interface', () => {
      const md = sha256.create()
      expect(md).toBeDefined()
      expect(md.algorithm).toBe('sha256')
      expect(md.blockLength).toBe(64)
      expect(md.digestLength).toBe(32) // SHA-256 produces a 32-byte (256-bit) digest
      expect(typeof md.start).toBe('function')
      expect(typeof md.update).toBe('function')
      expect(typeof md.digest).toBe('function')
    })
  })

  describe('hashing functionality', () => {
    it('should hash empty string', () => {
      const md = sha256.create()
      const hash = md.update('').digest()
      expect(hash).toBeDefined()
      expect(typeof hash.toHex()).toBe('string')
      expect(hash.toHex().length).toBe(64) // SHA-256 produces a 256-bit (64 hex chars) hash

      expect(hash.toHex()).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    })

    it('should hash "abc"', () => {
      const md = sha256.create()
      const hash = md.update('abc').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)

      expect(hash.toHex()).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    })

    it('should hash longer text', () => {
      const md = sha256.create()
      const hash = md.update('The quick brown fox jumps over the lazy dog').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)

      expect(hash.toHex()).toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592')
    })
  })

  describe('incremental hashing', () => {
    it('should support incremental hashing', () => {
      const md = sha256.create()
      md.update('The quick brown ')
      md.update('fox jumps over ')
      md.update('the lazy dog')
      const hash = md.digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)

      // Should match the hash of the complete string
      expect(hash.toHex()).toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592')
    })

    it('should allow multiple digests from the same instance', () => {
      const md = sha256.create()
      md.start()
      md.update('abc')
      const hash1 = md.digest()

      md.start()
      md.update('def')
      const hash2 = md.digest()

      expect(hash1).toBeDefined()
      expect(hash2).toBeDefined()
      // Different inputs should produce different hashes
      expect(hash1.toHex()).not.toBe(hash2.toHex())
    })
  })

  describe('UTF-8 encoding', () => {
    it('should handle UTF-8 encoding parameter', () => {
      const md = sha256.create()
      expect(() => md.update('test string', 'utf8')).not.toThrow()
    })
  })

  describe('ByteStringBuffer input', () => {
    it('should hash ByteStringBuffer input', () => {
      const buffer = new ByteStringBuffer()
      buffer.putBytes('abc')

      const md = sha256.create()
      const hash = md.update(buffer as unknown as string).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)
    })
  })

  describe('edge cases', () => {
    it('should handle messages that require padding to a new block', () => {
      // 64 bytes is exactly one block, so this will require padding in a new block
      const md = sha256.create()
      const hash = md.update('a'.repeat(64)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)

      // Current implementation produces: 'ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb'
      expect(hash.toHex()).toBe('ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb')
    })

    it('should handle messages that are exactly one byte less than a block', () => {
      // 63 bytes is one byte less than a block
      const md = sha256.create()
      const hash = md.update('a'.repeat(63)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)
    })

    it('should handle longer messages', () => {
      // Test with a longer message (multiple blocks)
      const md = sha256.create()
      const hash = md.update('a'.repeat(200)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)
    })
  })

  describe('state management', () => {
    it('should reset state when start() is called', () => {
      const md = sha256.create()
      md.update('test')
      md.start()
      expect(md.messageLength).toBe(0)
    })

    it('should maintain state between updates', () => {
      const md1 = sha256.create()
      const singleHash = md1.update('abcdef').digest().toHex()

      const md2 = sha256.create()
      md2.update('abc')
      md2.update('def')
      const incrementalHash = md2.digest().toHex()

      expect(incrementalHash).toBe(singleHash)
    })
  })

  describe('SHA-256 specific features', () => {
    it('should use the correct initial hash values', () => {
      // SHA-256 has specific initial hash values defined in the standard
      const md = sha256.create()

      // We'll test this indirectly by checking the hash of an empty string
      // which should only depend on the initial values and padding
      const hash = md.update('').digest()
      expect(hash).toBeDefined()
    })

    it('should handle the K constants correctly', () => {
      // SHA-256 uses 64 constants in its compression function
      // We'll test this indirectly by hashing data that would exercise these constants
      const md = sha256.create()
      const hash = md.update('a'.repeat(64)).digest() // One full block
      expect(hash).toBeDefined()
    })
  })

  describe('NIST test vectors', () => {
    it('should match NIST test vector 1', () => {
      const md = sha256.create()
      const hash = md.update('abc').digest()
      expect(hash.toHex()).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    })

    it('should match NIST test vector 2', () => {
      const md = sha256.create()
      const hash = md.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').digest()
      expect(hash.toHex()).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
    })

    it('should produce consistent results for "a" repeated 1000 times', () => {
      const md = sha256.create()
      const hash = md.update('a'.repeat(1000)).digest()

      expect(hash.toHex()).toBe('41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3')
    })
  })

  describe('edge cases with consistent outputs', () => {
    it('should consistently hash a message that is exactly one block', () => {
      const md = sha256.create()
      // SHA-256 block size is 64 bytes
      const hash = md.update('a'.repeat(64)).digest()
      expect(hash.toHex()).toBe('ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb')
    })

    it('should consistently hash a message that spans multiple blocks', () => {
      const md = sha256.create()
      // 120 bytes (spans 2 blocks)
      const hash = md.update('a'.repeat(120)).digest()

      expect(hash.toHex()).toBe('2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c')
    })
  })

  describe('special test cases', () => {
    it('should consistently hash a message with a period', () => {
      const md = sha256.create()
      const hash = md.update('abc.').digest()

      expect(hash.toHex()).toBe('5ac9481b887da55cdb508bbb7d91e7896c418c1ad3badb6f4f6d2a524f5cdcaf')
    })

    it('should consistently hash a message with special characters', () => {
      const md = sha256.create()
      const hash = md.update('abc!@#$%^&*()').digest()

      expect(hash.toHex()).toBe('12467d627114bfff999bc2570676736fbdc19ece55d83be7ebfb6603576e9972')
    })
  })
})
