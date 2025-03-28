import { describe, it } from 'bun:test'

const ASSERT = require('node:assert')
const RC2 = require('../../lib/rc2')
const UTIL = require('../../lib/util');

(function () {
  describe('rc2', () => {
    it('should expand a 128-bit key', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const expect = '71ab26462f0b9333609d4476e48ab72438c2194b70a47085d84b6af1dc72119023b94fe80aee2b6b45f27f923d9be1570da3ce8b16ad7f78db166ffbc28a836a4392cf0b748085dae4b69bdc2a4679cdfc09d84317016987e0c5b765c91dc612b1f44d7921b3e2c46447508bd2ac02e119e0f42a89c719675da320cf3e8958cd'
      ASSERT.equal(RC2.expandKey(key).toHex(), expect)
    })

    it('should expand a 40-bit key', () => {
      const key = UTIL.hexToBytes('88bca90e90')
      const expect = 'af136d2243b94a0878d7a604f8d6d9fd64a698fd6ebc613e641f0d1612055ef6cb55966db8f32bfd9246dae99880be8a91433adf54ea546d9daad62db7a55f6c7790aa87ba67de0e9ea9128dfc7ccdddd7c47c33d2bb7f823729977f083b5dc1f5bb09000b98e12cdaaf22f80dcc88c37d2c2fd80402f8a30a9e41d356669471'
      ASSERT.equal(RC2.expandKey(key, 40).toHex(), expect)
    })

    it('should rc2-ecb encrypt zeros', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const input = new UTIL.createBuffer().fillWithByte(0, 8)
      const cipher = RC2.startEncrypting(key, null, null)
      cipher.update(input)
      cipher.finish()
      ASSERT.equal(cipher.output.toHex(), '2269552ab0f85ca6e35b3b2ce4e02191')
    })

    it('should rc2-ecb encrypt: vegan', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const input = new UTIL.createBuffer('vegan')
      const cipher = RC2.startEncrypting(key, null, null)
      cipher.update(input)
      cipher.finish()
      ASSERT.equal(cipher.output.toHex(), '2194adaf4d517e3a')
    })

    it('should rc2-ecb decrypt: 2194adaf4d517e3a', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const input = new UTIL.createBuffer(UTIL.hexToBytes('2194adaf4d517e3a'))
      const cipher = RC2.startDecrypting(key, null, null)
      cipher.update(input)
      cipher.finish()
      ASSERT.equal(cipher.output.getBytes(), 'vegan')
    })

    it('should rc2-cbc encrypt: revolution', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const iv = new UTIL.createBuffer(UTIL.hexToBytes('0123456789abcdef'))
      const input = new UTIL.createBuffer('revolution')
      const cipher = RC2.startEncrypting(key, iv, null)
      cipher.update(input)
      cipher.finish()
      ASSERT.equal(cipher.output.toHex(), '50cfd16e0fd7f20b17a622eb2a469b7e')
    })

    it('should rc2-cbc decrypt: 50cfd16e0fd7f20b17a622eb2a469b7e', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const iv = new UTIL.createBuffer(UTIL.hexToBytes('0123456789abcdef'))
      const input = new UTIL.createBuffer(
        UTIL.hexToBytes('50cfd16e0fd7f20b17a622eb2a469b7e'),
      )
      const cipher = RC2.startDecrypting(key, iv, null)
      cipher.update(input)
      cipher.finish()
      ASSERT.equal(cipher.output, 'revolution')
    })

    it('should rc2-cbc encrypt w/binary string iv: revolution', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const iv = UTIL.hexToBytes('0123456789abcdef')
      const input = new UTIL.createBuffer('revolution')
      const cipher = RC2.startEncrypting(key, iv, null)
      cipher.update(input)
      cipher.finish()
      ASSERT.equal(cipher.output.toHex(), '50cfd16e0fd7f20b17a622eb2a469b7e')
    })

    it('should rc2-cbc decrypt w/binary string iv: 50cfd16e0fd7f20b17a622eb2a469b7e', () => {
      const key = UTIL.hexToBytes('88bca90e90875a7f0f79c384627bafb2')
      const iv = UTIL.hexToBytes('0123456789abcdef')
      const input = new UTIL.createBuffer(
        UTIL.hexToBytes('50cfd16e0fd7f20b17a622eb2a469b7e'),
      )
      const cipher = RC2.startDecrypting(key, iv, null)
      cipher.update(input)
      cipher.finish()
      ASSERT.equal(cipher.output, 'revolution')
    })
  })
})()
