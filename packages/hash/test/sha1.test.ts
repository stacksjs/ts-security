import { describe, expect, it } from 'bun:test'
import { ByteStringBuffer } from 'ts-security-utils'
import { sha1 } from '../src/sha1'

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
      expect(hash.toHex()).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709')
    })

    it('should hash "abc"', () => {
      const md = sha1.create()
      const hash = md.update('abc').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('a9993e364706816aba3e25717850c26c9cd0d89d')
    })

    it('should hash longer text', () => {
      const md = sha1.create()
      const hash = md.update('The quick brown fox jumps over the lazy dog').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')
    })
  })

  describe('incremental hashing', () => {
    it('should support incremental hashing', () => {
      const md = sha1.create()
      md.update('THIS IS ')
      md.update('A MESSAGE')
      const hash = md.digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('5f24f4d6499fd2d44df6c6e94be8b14a796c071d')
    })

    it('should allow multiple digests from the same instance', () => {
      const md = sha1.create()
      md.start()
      md.update('THIS IS ')
      md.update('A MESSAGE')
      const hash1 = md.digest()
      const hash2 = md.digest()

      expect(hash1).toBeDefined()
      expect(hash2).toBeDefined()
      expect(hash1.toHex()).toBe('5f24f4d6499fd2d44df6c6e94be8b14a796c071d')
      expect(hash2.toHex()).toBe('5f24f4d6499fd2d44df6c6e94be8b14a796c071d')
    })
  })

  describe('UTF-8 encoding', () => {
    it('should handle UTF-8 encoding parameter', () => {
      const md = sha1.create()
      const hash = md.update('c\'\u00E8', 'utf8').digest()
      expect(hash.toHex()).toBe('98c9a3f804daa73b68a5660d032499a447350c0d')
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
      expect(hash.toHex()).toBe('a9993e364706816aba3e25717850c26c9cd0d89d')
    })
  })

  describe('edge cases', () => {
    it('should handle messages that require padding to a new block', () => {
      // 64 bytes is exactly one block, so this will require padding in a new block
      const md = sha1.create()
      const hash = md.update('a'.repeat(64)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('0098ba824b5c16427bd7a1122a5a442a25ec644d')
    })

    it('should handle messages that are exactly one byte less than a block', () => {
      // 63 bytes is one byte less than a block
      const md = sha1.create()
      const hash = md.update('a'.repeat(63)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('03f09f5b158a7a8cdad920bddc29b81c18a551f5')
    })

    it('should handle longer messages', () => {
      // Test with a longer message (multiple blocks)
      const md = sha1.create()
      const hash = md.update('a'.repeat(200)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(40)
      expect(hash.toHex()).toBe('e61cfffe0d9195a525fc6cf06ca2d77119c24a40')
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
      expect(incrementalHash).toBe('1f8ac10f23c5b5bc1167bda84b833e5c057a77d2')
    })
  })

  describe('long messages', () => {
    it('should hash 1 million "a" characters', () => {
      const md = sha1.create()
      const hash = md.update('a'.repeat(1000000)).digest()
      expect(hash.toHex()).toBe('34aa973cd4c4daa4f61eeb2bdbad27316534016f')
    })

    it('should hash 10000 repetitions of "abc"', () => {
      const md = sha1.create()
      for (let i = 0; i < 10000; ++i) {
        md.update('abc')
      }
      expect(md.digest().toHex()).toBe('a838edb5dec47b84b4bfb0a528ea958a5d9d2350')
    })
  })

  describe('NIST test vectors', () => {
    it('should match NIST test vector 1', () => {
      const md = sha1.create()
      const hash = md.update('abc').digest()
      expect(hash.toHex()).toBe('a9993e364706816aba3e25717850c26c9cd0d89d')
    })

    it('should match NIST test vector 2', () => {
      const md = sha1.create()
      const hash = md.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').digest()
      expect(hash.toHex()).toBe('84983e441c3bd26ebaae4aa1f95129e5e54670f1')
    })
  })

  describe('edge cases with consistent outputs', () => {
    it('should consistently hash a message that is exactly one block', () => {
      const md = sha1.create()
      // SHA-1 block size is 64 bytes
      const hash = md.update('a'.repeat(64)).digest()
      expect(hash.toHex()).toBe('0098ba824b5c16427bd7a1122a5a442a25ec644d')
    })

    it('should consistently hash a message that spans multiple blocks', () => {
      const md = sha1.create()
      // 120 bytes (spans 2 blocks)
      const hash = md.update('a'.repeat(120)).digest()
      expect(hash.toHex()).toBe('f34c1488385346a55709ba056ddd08280dd4c6d6')
    })
  })
})
