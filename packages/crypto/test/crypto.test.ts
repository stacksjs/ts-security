import { describe, expect, it } from 'bun:test'
import { decrypt, encrypt } from '../src/encrypt'
import { generateHex, generateKey, randomBytes, randomInt } from '../src/key'
import { hashPassword, verifyPassword } from '../src/password'

describe('AES-GCM encrypt/decrypt', () => {
  it('round-trips a message', async () => {
    const result = await encrypt('Hello, World!', 'correct horse battery staple')
    expect(result.algorithm).toBe('AES-GCM')
    const plaintext = await decrypt(result.encrypted, 'correct horse battery staple')
    expect(plaintext).toBe('Hello, World!')
  })

  it('always uses authenticated AES-GCM', async () => {
    const result = await encrypt('secret', 'pw')
    expect(result.algorithm).toBe('AES-GCM')
  })

  it('produces a unique salt and IV per call (no nonce reuse)', async () => {
    const a = await encrypt('same message', 'same passphrase')
    const b = await encrypt('same message', 'same passphrase')
    // Distinct IVs and distinct ciphertext for identical inputs.
    expect(a.iv).not.toBe(b.iv)
    expect(a.encrypted).not.toBe(b.encrypted)
  })

  it('rejects tampered ciphertext via the GCM auth tag', async () => {
    const { encrypted } = await encrypt('do not tamper', 'pw')
    const buf = Buffer.from(encrypted, 'base64')
    buf[buf.length - 1] ^= 0xFF // flip a bit in the auth tag region
    await expect(decrypt(buf.toString('base64'), 'pw')).rejects.toThrow()
  })

  it('fails to decrypt with the wrong passphrase', async () => {
    const { encrypted } = await encrypt('top secret', 'right-pass')
    await expect(decrypt(encrypted, 'wrong-pass')).rejects.toThrow()
  })

  it('rejects ciphertext that is too short to contain salt + IV + tag', async () => {
    await expect(decrypt('AAAA', 'pw')).rejects.toThrow('too short')
  })

  it('rejects a custom IV that is not exactly 12 bytes', async () => {
    await expect(encrypt('x', 'pw', { iv: new Uint8Array(16) })).rejects.toThrow('12 bytes')
    await expect(encrypt('x', 'pw', { iv: new Uint8Array(8) })).rejects.toThrow('12 bytes')
  })

  it('accepts a valid 12-byte custom IV', async () => {
    const iv = randomBytes(12)
    const { encrypted } = await encrypt('with custom iv', 'pw', { iv })
    expect(await decrypt(encrypted, 'pw')).toBe('with custom iv')
  })
})

describe('app key generation', () => {
  it('generates a key with >= 256 bits of entropy by default', () => {
    const key = generateKey()
    expect(key.startsWith('base64:')).toBe(true)
    const raw = Buffer.from(key.slice('base64:'.length), 'base64')
    expect(raw.length).toBe(32) // 32 bytes = 256 bits
  })

  it('produces distinct keys each call', () => {
    expect(generateKey()).not.toBe(generateKey())
    expect(generateHex()).not.toBe(generateHex())
  })
})

describe('randomInt', () => {
  it('stays within the inclusive range', () => {
    for (let i = 0; i < 5000; i++) {
      const v = randomInt(1, 6)
      expect(v).toBeGreaterThanOrEqual(1)
      expect(v).toBeLessThanOrEqual(6)
    }
  })

  it('handles a single-value range', () => {
    expect(randomInt(5, 5)).toBe(5)
  })
})

describe('password hashing', () => {
  it('hashes and verifies with the default algorithm', async () => {
    const hash = await hashPassword('s3cr3t-pw')
    expect(await verifyPassword('s3cr3t-pw', hash)).toBe(true)
    expect(await verifyPassword('wrong-pw', hash)).toBe(false)
  })

  it('supports argon2id with configurable cost', async () => {
    const hash = await hashPassword('s3cr3t-pw', { algorithm: 'argon2id', timeCost: 2 })
    expect(hash.startsWith('$argon2id$')).toBe(true)
    expect(await verifyPassword('s3cr3t-pw', hash)).toBe(true)
  })
})
