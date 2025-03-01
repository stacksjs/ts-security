import type { ByteStringBuffer } from 'ts-security-utils'

/**
 * SHA-256 module interface.
 */
export interface SHA256 {
  create: () => MessageDigest
}

// SHA-256 state interface
export interface SHA256State {
  h0: number
  h1: number
  h2: number
  h3: number
  h4: number
  h5: number
  h6: number
  h7: number
}

// Message digest interface
export interface MessageDigest {
  algorithm: string
  blockLength: number
  digestLength: number
  messageLength: number
  fullMessageLength: number[]
  messageLength64?: number[]
  messageLengthSize: number
  start: () => MessageDigest
  update: (msg: string | ByteStringBuffer, encoding?: string) => MessageDigest
  digest: () => ByteStringBuffer
}

// SHA-1 state contains five 32-bit integers
export interface SHA1State {
  h0: number
  h1: number
  h2: number
  h3: number
  h4: number
}

// SHA-512 state interface (each value is represented as two 32-bit integers)
export interface SHA512State {
  h0: [number, number]
  h1: [number, number]
  h2: [number, number]
  h3: [number, number]
  h4: [number, number]
  h5: [number, number]
  h6: [number, number]
  h7: [number, number]
}

// SHA-512 algorithm type
export type SHA512Algorithm = 'sha512' | 'sha384' | 'sha512/256' | 'sha512/224'

// Export the SHA-512 implementation
export interface SHA512 {
  create: () => MessageDigest
  sha384?: { create: () => MessageDigest }
  sha256?: { create: () => MessageDigest }
  sha224?: { create: () => MessageDigest }
}
