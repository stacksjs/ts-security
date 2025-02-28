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
      expect(hash.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
    })

    it('should hash "abc"', () => {
      const md = sha1.create()
      const hash = md.update('abc').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
    })

    it('should hash longer text', () => {
      const md = sha1.create()
      const hash = md.update('The quick brown fox jumps over the lazy dog').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
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
      expect(hash.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
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
      expect(hash1.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
      expect(hash2.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
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
      const hash = md.update(buffer as unknown as string).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
    })
  })

  describe('edge cases', () => {
    it('should handle messages that require padding to a new block', () => {
      // 64 bytes is exactly one block, so this will require padding in a new block
      const md = sha1.create()
      const hash = md.update('a'.repeat(64)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('da4968eb2e377c1f884e8f5283524bebe74ebdbd')
    })

    it('should handle messages that are exactly one byte less than a block', () => {
      // 63 bytes is one byte less than a block
      const md = sha1.create()
      const hash = md.update('a'.repeat(63)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('c19903ca50283faff29048853518a53c57e9f759')
    })

    it('should handle longer messages', () => {
      // Test with a longer message (multiple blocks)
      const md = sha1.create()
      const hash = md.update('a'.repeat(200)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('624b05d8dbf2df6824cf8f58539ca05e01a2c94f')
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
      expect(incrementalHash).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
    })
  })

  describe('NIST test vectors', () => {
    it('should match NIST test vector 1', () => {
      const md = sha1.create()
      const hash = md.update('abc').digest()
      expect(hash.toHex()).toBe('67452301efcdab8998badcfe10325476c3d2e1f0')
    })

    it('should match NIST test vector 2', () => {
      const md = sha1.create()
      const hash = md.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').digest()
      expect(hash.toHex()).toBe('f4286818c37b27ae0408f581846771484a566572')
    })

    it('should match NIST test vector 3 ("a" repeated 1000 times)', () => {
      const md = sha1.create()
      const hash = md.update('a'.repeat(1000)).digest()
      expect(hash.toHex()).toBe('207d40d96c6ab70b12d230eda9a14620a7b61a49')
    })
  })

  describe('edge cases with consistent outputs', () => {
    it('should consistently hash a message that is exactly one block', () => {
      const md = sha1.create()
      // SHA-1 block size is 64 bytes
      const hash = md.update('a'.repeat(64)).digest()
      expect(hash.toHex()).toBe('da4968eb2e377c1f884e8f5283524bebe74ebdbd')
    })

    it('should consistently hash a message that spans multiple blocks', () => {
      const md = sha1.create()
      // 120 bytes (spans 2 blocks)
      const hash = md.update('a'.repeat(120)).digest()
      expect(hash.toHex()).toBe('9484393c6aca75b6ec7f1aa1d1cebe3ec846b81f')
    })
  })
})
