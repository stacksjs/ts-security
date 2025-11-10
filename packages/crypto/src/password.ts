/**
 * Password hashing and verification using Bun's native password API
 */

export interface HashPasswordOptions {
  algorithm?: 'bcrypt' | 'argon2id' | 'argon2i' | 'argon2d'
  cost?: number // bcrypt cost (4-31)
  memoryCost?: number // argon2 memory cost in KB
  timeCost?: number // argon2 time cost (iterations)
}

/**
 * Hash a password using the specified algorithm
 */
export async function hashPassword(
  password: string,
  options?: HashPasswordOptions,
): Promise<string> {
  const algorithm = options?.algorithm || 'bcrypt'

  if (algorithm === 'bcrypt') {
    return await Bun.password.hash(password, {
      algorithm: 'bcrypt',
      cost: options?.cost || 10,
    })
  }

  // Argon2 variants
  return await Bun.password.hash(password, {
    algorithm,
    memoryCost: options?.memoryCost || 65536, // 64MB
    timeCost: options?.timeCost || 3,
  })
}

/**
 * Verify a password against a hash
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await Bun.password.verify(password, hash)
}

/**
 * Hash using Bcrypt specifically
 */
export async function bcrypt(password: string, cost: number = 10): Promise<string> {
  return await hashPassword(password, { algorithm: 'bcrypt', cost })
}

/**
 * Hash using Argon2id specifically
 */
export async function argon2id(
  password: string,
  options?: { memoryCost?: number, timeCost?: number },
): Promise<string> {
  return await hashPassword(password, {
    algorithm: 'argon2id',
    ...options,
  })
}

/**
 * Hash using Argon2i specifically
 */
export async function argon2i(
  password: string,
  options?: { memoryCost?: number, timeCost?: number },
): Promise<string> {
  return await hashPassword(password, {
    algorithm: 'argon2i',
    ...options,
  })
}

/**
 * Hash using Argon2d specifically
 */
export async function argon2d(
  password: string,
  options?: { memoryCost?: number, timeCost?: number },
): Promise<string> {
  return await hashPassword(password, {
    algorithm: 'argon2d',
    ...options,
  })
}
