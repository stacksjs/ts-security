/**
 * Key generation utilities using native crypto
 */

/**
 * Generate a random application key
 */
export function generateKey(length: number = 32): string {
  const random = crypto.getRandomValues(new Uint8Array(length))
  const base64 = Buffer.from(random).toString('base64')
  return `base64:${base64}`
}

/**
 * Generate a random hex string
 */
export function generateHex(length: number = 32): string {
  const random = crypto.getRandomValues(new Uint8Array(length))
  return Buffer.from(random).toString('hex')
}

/**
 * Generate a random UUID v4
 */
export function generateUUID(): string {
  return crypto.randomUUID()
}

/**
 * Generate random bytes
 */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length))
}

/**
 * Generate a secure random integer between min and max (inclusive)
 */
export function randomInt(min: number, max: number): number {
  const range = max - min + 1
  const bytesNeeded = Math.ceil(Math.log2(range) / 8)
  const maxValid = Math.floor(256 ** bytesNeeded / range) * range - 1

  let randomValue: number
  do {
    const randomBytes = crypto.getRandomValues(new Uint8Array(bytesNeeded))
    randomValue = randomBytes.reduce((acc, byte, i) => acc + byte * (256 ** i), 0)
  } while (randomValue > maxValid)

  return min + (randomValue % range)
}
