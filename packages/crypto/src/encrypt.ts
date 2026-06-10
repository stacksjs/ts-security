/**
 * AES Encryption/Decryption using Web Crypto API (Bun/Node/Browser compatible)
 */

export interface EncryptOptions {
  /**
   * Only authenticated AES-GCM is supported. Unauthenticated modes such as
   * raw AES-CBC are intentionally not offered because they are vulnerable to
   * tampering and padding-oracle attacks.
   */
  algorithm?: 'AES-GCM'
  keyLength?: 128 | 192 | 256
  /**
   * Optional 12-byte GCM nonce. Must be unique per key. If omitted a fresh
   * CSPRNG nonce is generated, which is the recommended usage.
   */
  iv?: Uint8Array
}

export interface EncryptResult {
  encrypted: string
  iv: string
  algorithm: string
}

/** AES-GCM standard nonce length in bytes. */
const GCM_IV_LENGTH = 12
/** PBKDF2 salt length in bytes. */
const SALT_LENGTH = 16

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
      salt: salt as BufferSource,
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
  const algorithm = 'AES-GCM'
  const keyLength = options?.keyLength || 256
  const iv = options?.iv || crypto.getRandomValues(new Uint8Array(GCM_IV_LENGTH))

  // GCM nonces must be exactly 12 bytes so that decrypt() can locate the
  // ciphertext boundary in the serialized salt||iv||ciphertext blob.
  if (iv.length !== GCM_IV_LENGTH)
    throw new Error(`AES-GCM IV must be exactly ${GCM_IV_LENGTH} bytes`)

  // Generate salt for key derivation
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))

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
): Promise<string> {
  // Decode from base64
  const combined = Buffer.from(encryptedData, 'base64')

  // The blob must contain salt + IV + at least the 16-byte GCM auth tag.
  const minLength = SALT_LENGTH + GCM_IV_LENGTH + 16
  if (combined.length < minLength)
    throw new Error('Invalid ciphertext: too short')

  // Extract salt, IV, and encrypted data
  const salt = combined.slice(0, SALT_LENGTH)
  const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + GCM_IV_LENGTH)
  const encrypted = combined.slice(SALT_LENGTH + GCM_IV_LENGTH)

  // Derive key from passphrase
  const key = await deriveKey(passphrase, salt)

  // Always decrypt with authenticated AES-GCM. The algorithm is fixed (never
  // caller-supplied) so a malicious ciphertext cannot downgrade the mode, and
  // GCM verifies the auth tag, rejecting any tampered ciphertext.
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
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
