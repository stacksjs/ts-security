import { describe, it, expect } from 'bun:test'
import { ed25519 } from '../../src/algorithms/asymmetric/ed25519'
import { sha256 } from '../../src/algorithms/hash/sha256'
import { ByteBuffer, decode64, encode64, hexToBytes } from '../../packages/wip/utils'

const b64PrivateKey = 'XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtjE20/RjGhpDRDhAKkHfQjKciEW7zmJamO56uXdT4rr+g=='
const b64PublicKey = 'xNtP0YxoaQ0Q4QCpB30IynIhFu85iWpjuerl3U+K6/o='
const b64Signature = 'DttvMHiwblQQ+f5uvqebITsJ5YFnDdoU7j4liFaynZeQB65Zs+MkQ2PxA978ALonGdIhCr2chw/sP53pDQVMCw=='
const b64BadSignature = 'AttvMHiwblQQ+f5uvqebITsJ5YFnDdoU7j4liFaynZeQB65Zs+MkQ2PxA978ALonGdIhCr2chw/sP53pDQVMCw=='
const b64Sha256Signature = 'sJwlB2ODjzFPe5mlyJHPkryCJDE6r5oVDGGtyPY/eomBKhAogWow/AYuZ9fZ/gGg4Jd2ub3SzLnzhkaUPUxQDA=='

describe('ed25519', () => {
  it('should generate a key pair from a seed', () => {
    const pwd = 'password'
    const md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })
    const privateKey = eb64(kp.privateKey)
    const publicKey = eb64(kp.publicKey)
    expect(privateKey).toBe(b64PrivateKey)
    expect(publicKey).toBe(b64PublicKey)
  })

  it('should get a public key from a private key', () => {
    const privateKey = db64(b64PrivateKey)
    const publicKey = ed25519.publicKeyFromPrivateKey({
      privateKey,
    })
    expect(eb64(publicKey)).toBe(b64PublicKey)
  })

  it('should generate a random key pair', () => {
    const kp = ed25519.generateKeyPair()
    expect(kp.privateKey).toBeTruthy()
    expect(kp.publicKey).toBeTruthy()
  })

  it('should sign a SHA-256 digest of an UTF-8 message', () => {
    const pwd = 'password'
    let md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })
    md = sha256.create()
    md.update('test', 'utf8')
    const signature = ed25519.sign({
      md,
      privateKey: kp.privateKey,
    })
    expect(eb64(signature)).toBe(b64Sha256Signature)
  })

  it('should sign a digest given 32 private key bytes', () => {
    const pwd = 'password'
    let md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })
    md = sha256.create()
    md.update('test', 'utf8')
    const privateKey = kp.privateKey.slice(0, 32)
    const signature = ed25519.sign({
      md,
      privateKey,
    })
    expect(eb64(signature)).toBe(b64Sha256Signature)
  })

  it('should sign a UTF-8 message', () => {
    const pwd = 'password'
    const md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })
    const signature = ed25519.sign({
      message: 'test',
      encoding: 'utf8',
      privateKey: kp.privateKey,
    })
    expect(eb64(signature)).toBe(b64Signature)
  })

  it('should sign a binary message', () => {
    const pwd = 'password'
    const md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })
    const signature = ed25519.sign({
      message: 'test',
      encoding: 'binary',
      privateKey: kp.privateKey,
    })
    expect(eb64(signature)).toBe(b64Signature)
  })

  it('should sign a forge ByteBuffer message', () => {
    const pwd = 'password'
    const md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })
    const signature = ed25519.sign({
      message: new ByteBuffer('test', 'utf8'),
      privateKey: kp.privateKey,
    })
    expect(eb64(signature)).toBe(b64Signature)
  })

  it('should sign a Uint8Array message', () => {
    const pwd = 'password'
    const md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })
    const message = new Uint8Array(4)
    message[0] = 't'.charCodeAt(0)
    message[1] = 'e'.charCodeAt(0)
    message[2] = 's'.charCodeAt(0)
    message[3] = 't'.charCodeAt(0)
    const signature = ed25519.sign({
      message,
      privateKey: kp.privateKey,
    })
    expect(eb64(signature)).toBe(b64Signature)
  })

  if (typeof Buffer !== 'undefined') {
    it('should sign a node.js Buffer message', () => {
      const pwd = 'password'
      const md = sha256.create()
      md.update(pwd, 'utf8')
      const seed = md.digest().getBytes()
      const kp = ed25519.generateKeyPair({ seed })
      const signature = ed25519.sign({
        message: Buffer.from('test', 'utf8'),
        privateKey: kp.privateKey,
      })
      expect(eb64(signature)).toBe(b64Signature)
    })
  }

  it('should verify a signature', () => {
    const pwd = 'password'
    const md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })

    const signature = db64(b64Signature)

    const verified = ed25519.verify({
      message: 'test',
      encoding: 'utf8',
      signature,
      publicKey: kp.publicKey,
    })
    expect(verified).toBe(true)
  })

  it('should verify a SHA-256 digest signature', () => {
    const pwd = 'password'
    let md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })

    const signature = db64(b64Sha256Signature)
    md = sha256.create()
    md.update('test', 'utf8')

    const verified = ed25519.verify({
      md,
      signature,
      publicKey: kp.publicKey,
    })
    expect(verified).toBe(true)
  })

  if (typeof Buffer !== 'undefined') {
    it('should verify a node.js Buffer signature', () => {
      const pwd = 'password'
      const md = sha256.create()
      md.update(pwd, 'utf8')
      const seed = md.digest().getBytes()
      const kp = ed25519.generateKeyPair({ seed })

      const signature = Buffer.from(db64(b64Signature).getBytes(), 'binary')

      const verified = ed25519.verify({
        message: 'test',
        encoding: 'utf8',
        signature,
        publicKey: kp.publicKey,
      })
      expect(verified).toBe(true)
    })
  }

  it('should generate a random key pair and sign and verify', () => {
    const kp = ed25519.generateKeyPair()
    expect(kp.privateKey).toBeTruthy()
    expect(kp.publicKey).toBeTruthy()

    const signature = ed25519.sign({
      message: 'test',
      encoding: 'utf8',
      privateKey: kp.privateKey,
    })

    const verified = ed25519.verify({
      message: 'test',
      encoding: 'utf8',
      signature,
      publicKey: kp.publicKey,
    })

    expect(verified).toBe(true)
  })

  it('should fail to verify a signature', () => {
    const pwd = 'password'
    const md = sha256.create()
    md.update(pwd, 'utf8')
    const seed = md.digest().getBytes()
    const kp = ed25519.generateKeyPair({ seed })

    const signature = db64(b64BadSignature)

    const verified = ed25519.verify({
      message: 'test',
      encoding: 'utf8',
      signature,
      publicKey: kp.publicKey,
    })
    expect(verified).toBe(false)
  })

  it('should sign and verify with a base64-decoded key pair', () => {
    const privateKey = db64(b64PrivateKey)
    const signature = ed25519.sign({
      message: 'test',
      encoding: 'utf8',
      privateKey,
    })
    expect(eb64(signature)).toBe(b64Signature)

    const publicKey = db64(b64PublicKey)
    const verified = ed25519.verify({
      message: 'test',
      encoding: 'utf8',
      signature,
      publicKey,
    })
    expect(verified).toBe(true)
  })

  it('should pass test vector 1', () => {
    let privateKey = hexToBytes(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    )
    const publicKey = hexToBytes(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    )
    privateKey += publicKey
    const expectedSignature
      = 'e5564300c360ac729086e2cc806e828a'
        + '84877f1eb8e5d974d873e06522490155'
        + '5fb8821590a33bacc61e39701cf9b46b'
        + 'd25bf5f0595bbe24655141438e7a100b'

    const message = new ByteBuffer()
    const signature = ed25519.sign({
      message,
      privateKey,
    })
    const verified = ed25519.verify({
      message,
      signature,
      publicKey,
    })
    expect(hex(signature)).toBe(expectedSignature)
    expect(verified).toBe(true)
  })

  it('should pass test vector 2', () => {
    let privateKey = hexToBytes('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')
    const publicKey = hexToBytes('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
    privateKey += publicKey
    const expectedSignature = '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'

    const message = new ByteBuffer()
    message.putByte(0x72)
    const signature = ed25519.sign({
      message,
      privateKey,
    })
    const verified = ed25519.verify({
      message,
      signature,
      publicKey,
    })
    expect(hex(signature)).toBe(expectedSignature)
    expect(verified).toBe(true)
  })

  it('should pass test vector 3', () => {
    let privateKey = hexToBytes('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7')
    const publicKey = hexToBytes('fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025')
    privateKey += publicKey
    const expectedSignature
      = '6291d657deec24024827e69c3abe01a3'
        + '0ce548a284743a445e3680d7db5ac3ac'
        + '18ff9b538d16f290ae67f760984dc659'
        + '4a7c15e9716ed28dc027beceea1ec40a'

    const message = new ByteBuffer()
    message.putByte(0xAF)
    message.putByte(0x82)
    const signature = ed25519.sign({
      message,
      privateKey,
    })
    const verified = ed25519.verify({
      message,
      signature,
      publicKey,
    })
    expect(hex(signature)).toBe(expectedSignature)
    expect(verified).toBe(true)
  })
})

function eb64(buffer: Buffer | Uint8Array) {
  return encode64(new ByteBuffer(buffer).bytes())
}

function db64(x: string) {
  return new ByteBuffer(decode64(x), 'binary')
}

function hex(x: Buffer | Uint8Array) {
  return new ByteBuffer(x).toHex()
}
