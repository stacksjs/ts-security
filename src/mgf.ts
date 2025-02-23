/**
 * Mask generation functions.
 *
 * @author Stefan Siegl
 * @author Chris Breuer
 */

import { sha1 } from './algorithms/hash/sha1'
import { mgf1 } from './mgf1'

export interface MGF {
  mgf1: (seed: string, maskLen: number) => string
}

export const mgf: MGF = {
  mgf1: (seed: string, maskLen: number) => mgf1.create(sha1.create()).generate(seed, maskLen),
}
