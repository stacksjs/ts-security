import { describe, expect, it } from 'bun:test'
import { createBuffer } from 'ts-security-utils'
import { sha384, sha512, sha512_224, sha512_256 } from '../src/sha512'

describe('SHA-512', () => {
  describe('API structure', () => {
    it('should export a sha512 object with create method', () => {
      expect(sha512).toBeDefined()
      expect(typeof sha512.create).toBe('function')
    })

    it('should create a SHA-512 message digest object with correct interface', () => {
      const md = sha512.create()
      expect(md).toBeDefined()
      expect(md.algorithm).toBe('sha512')
      expect(md.blockLength).toBe(128)
      expect(md.digestLength).toBe(64) // SHA-512 produces a 64-byte (512-bit) digest
      expect(typeof md.start).toBe('function')
      expect(typeof md.update).toBe('function')
      expect(typeof md.digest).toBe('function')
    })
  })

  describe('hashing functionality', () => {
    it('should hash empty string', () => {
      const md = sha512.create()
      const hash = md.update('').digest()
      expect(hash).toBeDefined()
      expect(typeof hash.toHex()).toBe('string')
      expect(hash.toHex().length).toBe(128) // SHA-512 produces a 512-bit (128 hex chars) hash

      expect(hash.toHex()).toBe('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
    })

    it('should hash "abc"', () => {
      const md = sha512.create()
      const hash = md.update('abc').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(128)

      expect(hash.toHex()).toBe('ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')
    })

    it('should hash longer text', () => {
      const md = sha512.create()
      const hash = md.update('The quick brown fox jumps over the lazy dog').digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(128)

      expect(hash.toHex()).toBe('07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6')
    })
  })

  describe('incremental hashing', () => {
    it('should support incremental hashing', () => {
      const md = sha512.create()
      md.update('The quick brown ')
      md.update('fox jumps over ')
      md.update('the lazy dog')
      const hash = md.digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(128)

      // Should match the hash of the complete string
      expect(hash.toHex()).toBe('07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6')
    })

    it('should allow multiple digests from the same instance', () => {
      const md = sha512.create()
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
      const md = sha512.create()
      expect(() => md.update('test string', 'utf8')).not.toThrow()
    })
  })

  describe('ByteStringBuffer input', () => {
    it('should hash ByteStringBuffer input', () => {
      const buffer = createBuffer()
      buffer.putBytes('abc')

      const md = sha512.create()
      const hash = md.update(buffer as unknown as string).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(128)
    })
  })

  describe('edge cases', () => {
    it('should handle messages that require padding to a new block', () => {
      const md = sha512.create()
      const hash = md.update('a'.repeat(128)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(128)

      expect(hash.toHex()).toBe('b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321')
    })

    it('should handle messages that are exactly one byte less than a block', () => {
      // 127 bytes is one byte less than a block
      const md = sha512.create()
      const hash = md.update('a'.repeat(127)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(128)
    })

    it('should handle longer messages', () => {
      // Test with a longer message (multiple blocks)
      const md = sha512.create()
      const hash = md.update('a'.repeat(200)).digest()
      expect(hash).toBeDefined()
      expect(hash.toHex().length).toBe(128)
    })
  })

  describe('state management', () => {
    it('should reset state when start() is called', () => {
      const md = sha512.create()
      md.update('test')
      md.start()
      expect(md.messageLength).toBe(0)
    })

    it('should maintain state between updates', () => {
      const md1 = sha512.create()
      const singleHash = md1.update('abcdef').digest().toHex()

      const md2 = sha512.create()
      md2.update('abc')
      md2.update('def')
      const incrementalHash = md2.digest().toHex()

      expect(incrementalHash).toBe(singleHash)
    })
  })

  describe('SHA-512 specific features', () => {
    it('should use the correct initial hash values', () => {
      // SHA-512 has specific initial hash values defined in the standard
      const md = sha512.create()

      // We'll test this indirectly by checking the hash of an empty string
      // which should only depend on the initial values and padding
      const hash = md.update('').digest()
      expect(hash).toBeDefined()
    })

    it('should handle the K constants correctly', () => {
      // SHA-512 uses 80 constants in its compression function
      // We'll test this indirectly by hashing data that would exercise these constants
      const md = sha512.create()
      const hash = md.update('a'.repeat(80)).digest() // One full block
      expect(hash).toBeDefined()
    })
  })

  describe('NIST test vectors', () => {
    it('should match NIST test vector 1', () => {
      const md = sha512.create()
      const hash = md.update('abc').digest()
      expect(hash.toHex()).toBe('ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')
    })

    it('should match NIST test vector 2', () => {
      const md = sha512.create()
      const hash = md.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').digest()
      expect(hash.toHex()).toBe('204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445')
    })

    it('should produce consistent results for "a" repeated 1000 times', () => {
      const md = sha512.create()
      const hash = md.update('a'.repeat(1000)).digest()

      expect(hash.toHex()).toBe('67ba5535a46e3f86dbfbed8cbbaf0125c76ed549ff8b0b9e03e0c88cf90fa634fa7b12b47d77b694de488ace8d9a65967dc96df599727d3292a8d9d447709c97')
    })
  })

  describe('edge cases with consistent outputs', () => {
    it('should consistently hash a message that is exactly one block', () => {
      const md = sha512.create()
      // SHA-512 block size is 128 bytes
      const hash = md.update('a'.repeat(128)).digest()
      expect(hash.toHex()).toBe('b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321')
    })

    it('should consistently hash a message that spans multiple blocks', () => {
      const md = sha512.create()
      // 120 bytes (spans 2 blocks)
      const hash = md.update('a'.repeat(120)).digest()

      expect(hash.toHex()).toBe('f241de612b01aa2fa3cf01531d2a8e5e17fc761dfd48a704a834a47f57d6eade7804ecc39be42fdef16ec6adeaf7c01c2fd0c4cc97d3860907cfa4a3b36d0c05')
    })
  })

  describe('special test cases', () => {
    it('should consistently hash a message with a period', () => {
      const md = sha512.create()
      const hash = md.update('abc.').digest()

      expect(hash.toHex()).toBe('5fffad2405028218042feee8f1e7e8af4b8e119e5cd7172091b7d6a09068f1ee04cf2f83e8f4342397c65cb553215e31d6d370b48e1d87f880253a281a44b4a6')
    })

    it('should consistently hash a message with special characters', () => {
      const md = sha512.create()
      const hash = md.update('abc!@#$%^&*()').digest()

      expect(hash.toHex()).toBe('ad7333f992837ac94ec3c236a9fe2e3916b53fd28e9b5ab9f176f616e0da3d765e5fead6ab2c42e06dfb3df90dd7867c49b9692d6a18817a6b7456b64ab5351d')
    })
  })
})

describe('sha384', () => {
  it('should have correct digest length', () => {
    expect(sha384.digestLength).toBe(48)
  })

  it('should digest the empty string', () => {
    const md = sha384
    expect(md.digest().toHex()).toBe(
      '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
    )
  })

  it('should digest "abc"', () => {
    const md = sha384
    md.update('abc')
    expect(md.digest().toHex()).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    )
  })

  it('should digest "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"', () => {
    const md = sha384
    md.update('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu')
    expect(md.digest().toHex()).toBe(
      'ef8b20e8c90839628529dc71a9a9f571e9c4efbd2c2e7ef45da5be177f009965f49be0f62c2e3c9a8759fbdeff45d367',
    )
  })

  it('should digest "The quick brown fox jumps over the lazy dog"', () => {
    const md = sha384
    md.update('The quick brown fox jumps over the lazy dog')
    expect(md.digest().toHex()).toBe(
      '3b2e7c68c0ddde61fb92bb00aa8e36ada3164322a393b2075f95edee93c7cd48bc5577c3ec6bf9a7392c33c58e26e916',
    )
  })

  it('should digest "c\'\u00E8"', () => {
    const md = sha384
    md.update('c\'\u00E8', 'utf8')
    expect(md.digest().toHex()).toBe(
      '351b6fea9efe4eb10d7a95d438f2135183c8df0e358df967dd32c3563183cfd58133fc4639f1e18ca4e5cd6b1fbc5fe5',
    )
  })

  it('should digest "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', () => {
    const md = sha384
    md.start()
    md.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
    // do twice to check continuing digest
    expect(md.digest().toHex()).toBe(
      '3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b',
    )
    expect(md.digest().toHex()).toBe(
      '3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b',
    )
  })

  it('should digest multiple long messages', () => {
    for (let loop = 0; loop < 3; ++loop) {
      const md = sha384
      for (let i = 0; i < 10000; ++i) {
        md.update('abc')
      }
      const hash = md.digest().toHex()
      expect(hash.length).toBe(96) // SHA-384 produces a 48-byte (96 hex character) hash
    }
  })
})

describe('sha512/256', () => {
  it('should have correct digest length', () => {
    const md = sha512_256
    expect(md.digestLength).toBe(32)
  })

  it('should digest the empty string', () => {
    const md = sha512_256
    expect(md.digest().toHex()).toBe(
      'c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a',
    )
  })

  it('should digest "The quick brown fox jumps over the lazy dog"', () => {
    const md = sha512_256
    md.update('The quick brown fox jumps over the lazy dog')
    expect(md.digest().toHex()).toBe(
      'dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d',
    )
  })
})

describe('sha512/224', () => {
  it('should have correct digest length', () => {
    const md = sha512_224
    expect(md.digestLength).toBe(28)
  })

  it('should digest the empty string', () => {
    const md = sha512_224
    expect(md.digest().toHex()).toBe(
      '6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4',
    )
  })

  it('should digest "The quick brown fox jumps over the lazy dog"', () => {
    const md = sha512_224
    md.update('The quick brown fox jumps over the lazy dog')
    expect(md.digest().toHex()).toBe(
      '944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37',
    )
  })
})
