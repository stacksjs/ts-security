import { md5 } from './algorithms/hash/md5'
import { sha1 } from './algorithms/hash/sha1'
import { sha256 } from './algorithms/hash/sha256'
import { sha384 } from './algorithms/hash/sha384'
import { sha512 } from './algorithms/hash/sha512'

export interface MessageDigest {
  sha1: typeof sha1
  md5: typeof md5
  sha256: typeof sha256
  sha384: typeof sha384
  sha512: typeof sha512
}

export const md: MessageDigest = {
  sha1,
  sha256,
  sha384,
  sha512,
  md5,
}
