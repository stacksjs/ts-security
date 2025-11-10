/**
 * Hashing utilities using Bun native crypto
 */

export interface HashOptions {
  algorithm?: 'md5' | 'sha1' | 'sha256' | 'sha512' | 'blake2b256'
  encoding?: 'hex' | 'base64'
}

/**
 * Generate a hash using Bun's native crypto
 */
export function hash(input: string | Buffer, options?: HashOptions): string {
  const algorithm = options?.algorithm || 'sha256'
  const encoding = options?.encoding || 'hex'

  const hasher = new Bun.CryptoHasher(algorithm)
  hasher.update(input)

  return hasher.digest(encoding)
}

/**
 * Generate MD5 hash
 */
export function md5(input: string | Buffer, encoding: 'hex' | 'base64' = 'hex'): string {
  return hash(input, { algorithm: 'md5', encoding })
}

/**
 * Generate SHA1 hash
 */
export function sha1(input: string | Buffer, encoding: 'hex' | 'base64' = 'hex'): string {
  return hash(input, { algorithm: 'sha1', encoding })
}

/**
 * Generate SHA256 hash
 */
export function sha256(input: string | Buffer, encoding: 'hex' | 'base64' = 'hex'): string {
  return hash(input, { algorithm: 'sha256', encoding })
}

/**
 * Generate SHA512 hash
 */
export function sha512(input: string | Buffer, encoding: 'hex' | 'base64' = 'hex'): string {
  return hash(input, { algorithm: 'sha512', encoding })
}

/**
 * Generate BLAKE2b-256 hash
 */
export function blake2b256(input: string | Buffer, encoding: 'hex' | 'base64' = 'hex'): string {
  return hash(input, { algorithm: 'blake2b256', encoding })
}

/**
 * Generate HMAC
 */
export function hmac(
  input: string | Buffer,
  key: string,
  algorithm: 'sha256' | 'sha512' = 'sha256',
  encoding: 'hex' | 'base64' = 'hex',
): string {
  const hasher = new Bun.CryptoHasher(algorithm, key)
  hasher.update(input)
  return hasher.digest(encoding)
}
