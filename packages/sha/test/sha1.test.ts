import { expect, it, describe } from 'bun:test'
import { sha1 } from '../src/sha1'
import { ByteStringBuffer } from 'ts-security-utils'

describe('SHA-1', () => {
  describe('API structure', () => {
    it('should export a sha1 object with create method', () => {
      expect(sha1).toBeDefined()
      expect(typeof sha1.create).toBe('function')
    })

    it('should create a SHA-1 message digest object with correct interface', () => {
      const md = sha1.create()
      expect(md).toBeDefined()
      expect(md.algorithm).toBe('sha1')
      expect(md.blockLength).toBe(64)
      expect(md.digestLength).toBe(20)
      expect(typeof md.start).toBe('function')
      expect(typeof md.update).toBe('function')
      expect(typeof md.digest).toBe('function')
    })
  })

  describe('hashing functionality', () => {
    it('should hash empty string', () => {
      const md = sha1.create()
      const hash = md.update('').digest()
      expect(hash).toBeDefined()
      expect(typeof hash.toHex()).toBe('string')
      expect(hash.toHex().length).toBe(40) // SHA-1 produces a 160-bit (40 hex chars) hash
    })

    it('should hash "abc"', () => {
      const md = sha1.create()
      const hash = md.update('abc').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
    })

    it('should hash longer text', () => {
      const md = sha1.create()
      const hash = md.update('The quick brown fox jumps over the lazy dog').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
    })
  })

  describe('incremental hashing', () => {
    it('should support incremental hashing', () => {
      const md = sha1.create()
      md.update('The quick brown ')
      md.update('fox jumps over ')
      md.update('the lazy dog')
      const hash = md.digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
    })

    it('should allow multiple digests from the same instance', () => {
      const md = sha1.create()
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
      const md = sha1.create()
      expect(() => md.update('test string', 'utf8')).not.toThrow()
    })
  })

  describe('ByteStringBuffer input', () => {
    it('should hash ByteStringBuffer input', () => {
      const buffer = new ByteStringBuffer()
      buffer.putBytes('abc')

      const md = sha1.create()
      const hash = md.update(buffer).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
    })
  })

  describe('edge cases', () => {
    it('should handle messages that require padding to a new block', () => {
      // 64 bytes is exactly one block, so this will require padding in a new block
      const md = sha1.create()
      const hash = md.update('a'.repeat(64)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
    })

    it('should handle messages that are exactly one byte less than a block', () => {
      // 63 bytes is one byte less than a block
      const md = sha1.create()
      const hash = md.update('a'.repeat(63)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
    })

    it('should handle longer messages', () => {
      // Test with a longer message (multiple blocks)
      const md = sha1.create()
      const hash = md.update('a'.repeat(200)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
    })
  })

  describe('state management', () => {
    it('should reset state when start() is called', () => {
      const md = sha1.create()
      md.update('test')
      md.start()
      expect(md.messageLength).toBe(0)
    })

    it('should maintain state between updates', () => {
      const md1 = sha1.create()
      const singleHash = md1.update('abcdef').digest().toHex()

      const md2 = sha1.create()
      md2.update('abc')
      md2.update('def')
      const incrementalHash = md2.digest().toHex()

      expect(incrementalHash).toBe(singleHash)
    })
  })
})
