/**
 * TypeScript implementation of mask generation function MGF1.
 *
 * @author Stefan Siegl
 * @author Dave Longley
 * @author Chris Breuer
 */

import type { ByteStringBuffer } from './utils'
import { ByteBuffer } from './utils'

interface MessageDigest {
  start: () => void
  update: (data: string | ByteStringBuffer) => void
  digest: () => ByteStringBuffer
  digestLength: number
}

/**
 * Creates a MGF1 mask generation function object.
 *
 * @param md the message digest API to use (eg: forge.md.sha1.create()).
 *
 * @return a mask generation function object.
 */
export function create(md: MessageDigest) {
  /**
   * Generate mask of specified length.
   *
   * @param {string} seed The seed for mask generation.
   * @param maskLen Number of bytes to generate.
   * @return The generated mask.
   */
  function generate(seed: string, maskLen: number): string {
    // 2. Let T be the empty octet string.
    const t = new ByteBuffer()

    // 3. For counter from 0 to ceil(maskLen / hLen), do the following:
    const len = Math.ceil(maskLen / md.digestLength)
    for (let i = 0; i < len; i++) {
      // a. Convert counter to an octet string C of length 4 octets
      const c = new ByteBuffer()
      c.putInt32(i)

      // b. Concatenate the hash of the seed mgfSeed and C to the octet string T:
      md.start()
      md.update(seed + c.getBytes())
      t.putBuffer(new ByteBuffer(md.digest().getBytes()))
    }

    // output the leading maskLen octets of T as the octet string mask
    t.truncate(t.length() - maskLen)

    return t.getBytes()
  }

  return {
    generate,
  } as { generate: (seed: string, maskLen: number) => string }
}

export interface MGF1 {
  create: (md: MessageDigest) => {
    generate: (seed: string, maskLen: number) => string
  }
}

export const mgf1: MGF1 = {
  create,
}

export default mgf1
