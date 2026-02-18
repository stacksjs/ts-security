/**
 * AES Encryption/Decryption using Web Crypto API (Bun/Node/Browser compatible)
 */

export interface EncryptOptions {
  algorithm?: 'AES-GCM' | 'AES-CBC'
  keyLength?: 128 | 192 | 256
  iv?: Uint8Array
}

export interface EncryptResult {
  encrypted: string
  iv: string
  algorithm: string
}

/**
 * Generate a cryptographic key from a passphrase using PBKDF2
 */
async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  keyLength: number = 256,
): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passphraseKey,
    { name: 'AES-GCM', length: keyLength },
    false,
    ['encrypt', 'decrypt'],
  )
}

/**
 * Encrypt a message using AES-GCM
 */
export async function encrypt(
  message: string,
  passphrase: string,
  options?: EncryptOptions,
): Promise<EncryptResult> {
  const algorithm = options?.algorithm || 'AES-GCM'
  const keyLength = options?.keyLength || 256
  const iv = options?.iv || crypto.getRandomValues(new Uint8Array(12))

  // Generate salt for key derivation
  const salt = crypto.getRandomValues(new Uint8Array(16))

  // Derive key from passphrase
  const key = await deriveKey(passphrase, salt, keyLength)

  // Encrypt the message
  const encoder = new TextEncoder()
  const encrypted = await crypto.subtle.encrypt(
    {
      name: algorithm,
      iv: iv as BufferSource,
    },
    key,
    encoder.encode(message),
  )

  // Combine salt + IV + encrypted data
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength)
  combined.set(salt, 0)
  combined.set(iv, salt.length)
  combined.set(new Uint8Array(encrypted), salt.length + iv.length)

  // Convert to base64
  return {
    encrypted: Buffer.from(combined).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    algorithm,
  }
}

/**
 * Decrypt a message using AES-GCM
 */
export async function decrypt(
  encryptedData: string,
  passphrase: string,
  algorithm: string = 'AES-GCM',
): Promise<string> {
  // Decode from base64
  const combined = Buffer.from(encryptedData, 'base64')

  // Extract salt, IV, and encrypted data
  const salt = combined.slice(0, 16)
  const iv = combined.slice(16, 28) // 12 bytes for GCM
  const encrypted = combined.slice(28)

  // Derive key from passphrase
  const key = await deriveKey(passphrase, salt)

  // Decrypt the message
  const decrypted = await crypto.subtle.decrypt(
    {
      name: algorithm,
      iv: iv as BufferSource,
    },
    key,
    encrypted,
  )

  // Convert back to string
  const decoder = new TextDecoder()
  return decoder.decode(decrypted)
}

/**
 * Simple base64 encode (Bun native)
 */
export function base64Encode(input: string): string {
  return Buffer.from(input, 'utf-8').toString('base64')
}

/**
 * Simple base64 decode (Bun native)
 */
export function base64Decode(input: string): string {
  return Buffer.from(input, 'base64').toString('utf-8')
}
