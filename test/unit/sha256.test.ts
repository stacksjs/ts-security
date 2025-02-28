import { describe, it, expect } from 'bun:test'
import { sha256 as SHA256 } from '../../src/algorithms/hash/sha256'
import { fillString } from '../../packages/wip/utils'

describe('sha256', () => {
  it('should have correct digest length', () => {
    const md = SHA256.create()
    expect(md.digestLength).toBe(32)
  })

  it('should digest the empty string', () => {
    const md = SHA256.create()
    expect(md.digest().toHex()).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  it('should digest "abc"', () => {
    const md = SHA256.create()
    md.update('abc')
    expect(md.digest().toHex()).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  it('should digest "The quick brown fox jumps over the lazy dog"', () => {
    const md = SHA256.create()
    md.update('The quick brown fox jumps over the lazy dog')
    expect(md.digest().toHex()).toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592')
  })

  it('should digest "c\'\u00E8"', () => {
    const md = SHA256.create()
    md.update('c\'\u00E8', 'utf8')
    expect(md.digest().toHex()).toBe('1aa15c717afffd312acce2217ce1c2e5dabca53c92165999132ec9ca5decdaca')
  })

  it('should digest "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', () => {
    const md = SHA256.create()
    md.start()
    md.update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
    // do twice to check continuing digest
    expect(md.digest().toHex()).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
    expect(md.digest().toHex()).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
  })

  it('should digest a long message', () => {
    // Note: might be too slow on old browsers
    const md = SHA256.create()
    md.update(fillString('a', 1000000))
    expect(md.digest().toHex()).toBe('cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
  })

  it('should digest multiple long messages', () => {
    // Note: might be too slow on old browsers
    // done multiple times to check hot loop optimizations
    for (let loop = 0; loop < 3; ++loop) {
      const md = SHA256.create()
      for (let i = 0; i < 10000; ++i) {
        md.update('abc')
      }
      expect(md.digest().toHex()).toBe('13b77af908a78a94f2e21cf8fc137ea16c8020873eeee7b6b96b6b0975555a02')
    }
  })
})
