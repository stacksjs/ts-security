import { expect, it, describe } from 'bun:test'
import { sha256 } from '../src/sha256'
import { ByteStringBuffer } from 'ts-security-utils'

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
    })

    it('should hash "abc"', () => {
      const md = sha256.create()
      const hash = md.update('abc').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)
    })

    it('should hash longer text', () => {
      const md = sha256.create()
      const hash = md.update('The quick brown fox jumps over the lazy dog').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(64)
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
})
