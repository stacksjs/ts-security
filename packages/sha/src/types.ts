import type { ByteStringBuffer } from "ts-security-utils"

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

// SHA-512 algorithm type
export type SHA512Algorithm = 'SHA-512' | 'SHA-384' | 'SHA-512/256' | 'SHA-512/224'


// Export the SHA-512 implementation
export interface SHA512 {
  create: (algorithm?: SHA512Algorithm) => MessageDigest
  sha384: { create: () => MessageDigest }
  sha256: { create: () => MessageDigest }
  sha224: { create: () => MessageDigest }
}
