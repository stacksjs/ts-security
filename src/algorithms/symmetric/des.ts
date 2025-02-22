/**
 * DES (Data Encryption Standard) implementation.
 *
 * This implementation supports DES as well as 3DES-EDE in ECB and CBC mode.
 * It is based on the BSD-licensed implementation by Paul Tero:
 *
 * Paul Tero, July 2001
 * http://www.tero.co.uk/des/
 *
 * Optimized for performance with large blocks by
 * Michael Hayworth, November 2001
 * http://www.netdealing.com
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @author Stefan Siegl
 * @author Dave Longley
 * @author Chris Breuer
 */

import type { Algorithm, BlockCipher } from './cipher'
import type { CipherMode, CipherModeOptions } from './cipher-modes'
import { createCipher, registerAlgorithm as registerAlgo } from './cipher'
import { modes } from './cipher-modes'
import { ByteStringBuffer, createBuffer } from './utils'

/**
 * Creates a new DES cipher algorithm object.
 *
 * @param name the name of the algorithm.
 * @param mode the mode factory function.
 *
 * @return the DES algorithm object.
 */
export class DESAlgorithm implements Algorithm {
  name: string
  mode: CipherMode
  private _init: boolean
  private _keys!: number[]

  constructor(name: string, modeFactory: (options?: Partial<CipherModeOptions>) => CipherMode) {
    const self = this
    this._init = false
    this.name = name
    this.mode = modeFactory({
      blockSize: 8,
      cipher: {
        encrypt(inBlock: ByteStringBuffer, outBlock: ByteStringBuffer): void {
          _updateBlock(self._keys, inBlock, outBlock, false)
        },
        decrypt(inBlock: ByteStringBuffer, outBlock: ByteStringBuffer): void {
          _updateBlock(self._keys, inBlock, outBlock, true)
        },
      },
    })
  }

  /**
   * Initializes this DES algorithm by expanding its key.
   *
   * @param options the options to use.
   * @param options.key the key to use with this algorithm.
   * @param options.decrypt true if the algorithm should be initialized for decryption, false for encryption.
   * @param options.output optional output buffer.
   */
  initialize(options: {
    key: string | ByteStringBuffer
    decrypt?: boolean
    output?: ByteStringBuffer
  }): void {
    if (this._init)
      return

    const key = options.key instanceof ByteStringBuffer ? options.key : createBuffer(options.key)
    if (this.name.indexOf('3DES') === 0) {
      if (key.length() !== 24)
        throw new Error(`Invalid Triple-DES key size: ${key.length() * 8} bits`)
    }
    else {
      if (key.length() !== 8)
        throw new Error(`Invalid DES key size: ${key.length() * 8} bits`)
    }

    // do key expansion to 16 or 48 subkeys (single or triple DES)
    this._keys = _createKeys(key)
    this._init = true
  }
}

/** Register DES algorithms */
function registerAlgorithm(name: string, modeFactory: (options?: Partial<CipherModeOptions>) => CipherMode) {
  const factory = function () {
    return new DESAlgorithm(name, modeFactory)
  }
  registerAlgo(name, factory)
}

registerAlgorithm('DES-ECB', modes.ecb)
registerAlgorithm('DES-CBC', modes.cbc)
registerAlgorithm('DES-CFB', modes.cfb)
registerAlgorithm('DES-OFB', modes.ofb)
registerAlgorithm('DES-CTR', modes.ctr)

registerAlgorithm('3DES-ECB', modes.ecb)
registerAlgorithm('3DES-CBC', modes.cbc)
registerAlgorithm('3DES-CFB', modes.cfb)
registerAlgorithm('3DES-OFB', modes.ofb)
registerAlgorithm('3DES-CTR', modes.ctr)

const spfunction1 = [0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004]
const spfunction2 = [-0x7FEF7FE0, -0x7FFF8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7FEFFFE0, -0x7FFF7FE0, -0x7FFFFFE0, -0x7FEF7FE0, -0x7FEF8000, -0x80000000, -0x7FFF8000, 0x100000, 0x20, -0x7FEFFFE0, 0x108000, 0x100020, -0x7FFF7FE0, 0, -0x80000000, 0x8000, 0x108020, -0x7FF00000, 0x100020, -0x7FFFFFE0, 0, 0x108000, 0x8020, -0x7FEF8000, -0x7FF00000, 0x8020, 0, 0x108020, -0x7FEFFFE0, 0x100000, -0x7FFF7FE0, -0x7FF00000, -0x7FEF8000, 0x8000, -0x7FF00000, -0x7FFF8000, 0x20, -0x7FEF7FE0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020, -0x7FEF8000, 0x100000, -0x7FFFFFE0, 0x100020, -0x7FFF7FE0, -0x7FFFFFE0, 0x100020, 0x108000, 0, -0x7FFF8000, 0x8020, -0x80000000, -0x7FEFFFE0, -0x7FEF7FE0, 0x108000]
const spfunction3 = [0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200]
const spfunction4 = [0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080]
const spfunction5 = [0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000, 0x2080100, 0x40000100]
const spfunction6 = [0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010]
const spfunction7 = [0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0, 0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002]
const spfunction8 = [0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000]

/**
 * Create necessary sub keys.
 *
 * @param key the 64-bit or 192-bit key buffer.
 *
 * @return the expanded keys.
 */
function _createKeys(key: ByteStringBuffer): number[] {
  const pc2bytes0 = [0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204]
  const pc2bytes1 = [0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101]
  const pc2bytes2 = [0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808]
  const pc2bytes3 = [0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000]
  const pc2bytes4 = [0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010]
  const pc2bytes5 = [0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420]
  const pc2bytes6 = [0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002]
  const pc2bytes7 = [0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800]
  const pc2bytes8 = [0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002, 0x2040002]
  const pc2bytes9 = [0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408, 0x10000408]
  const pc2bytes10 = [0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020]
  const pc2bytes11 = [0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200]
  const pc2bytes12 = [0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010]
  const pc2bytes13 = [0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105]

  // how many iterations (1 for des, 3 for triple des)
  // changed by Paul 16/6/2007 to use Triple DES for 9+ byte keys
  const iterations = key.length() > 8 ? 3 : 1

  // stores the return keys
  const keys = []

  // now define the left shifts which need to be done
  const shifts = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0]

  let n = 0; let tmp
  for (let j = 0; j < iterations; j++) {
    let left = key.getInt32()
    let right = key.getInt32()

    tmp = ((left >>> 4) ^ right) & 0x0F0F0F0F
    right ^= tmp
    left ^= (tmp << 4)

    tmp = ((left >>> 16) ^ right) & 0x0000FFFF
    right ^= tmp
    left ^= (tmp << 16)

    tmp = ((right >>> 2) ^ left) & 0x33333333
    left ^= tmp
    right ^= (tmp << 2)

    tmp = ((right >>> 8) ^ left) & 0x00FF00FF
    left ^= tmp
    right ^= (tmp << 8)

    tmp = ((left >>> 1) ^ right) & 0x55555555
    right ^= tmp
    left ^= (tmp << 1)

    // right needs to be shifted and OR'd with last four bits of left
    tmp = (left << 8) | ((right >>> 20) & 0x000000F0)

    // left needs to be put upside down
    left = ((right << 24) | ((right << 8) & 0xFF0000)
      | ((right >>> 8) & 0xFF00) | ((right >>> 24) & 0xF0))
    right = tmp

    // now go through and perform these shifts on the left and right keys
    for (let i = 0; i < shifts.length; ++i) {
      // shift the keys either one or two bits to the left
      if (shifts[i]) {
        left = (left << 2) | (left >>> 26)
        right = (right << 2) | (right >>> 26)
      }
      else {
        left = (left << 1) | (left >>> 27)
        right = (right << 1) | (right >>> 27)
      }
      left &= -0xF
      right &= -0xF

      // now apply PC-2, in such a way that E is easier when encrypting or
      // decrypting this conversion will look like PC-2 except only the last 6
      // bits of each byte are used rather than 48 consecutive bits and the
      // order of lines will be according to how the S selection functions will
      // be applied: S2, S4, S6, S8, S1, S3, S5, S7
      const lefttmp = (
        pc2bytes0[left >>> 28] | pc2bytes1[(left >>> 24) & 0xF]
        | pc2bytes2[(left >>> 20) & 0xF] | pc2bytes3[(left >>> 16) & 0xF]
        | pc2bytes4[(left >>> 12) & 0xF] | pc2bytes5[(left >>> 8) & 0xF]
        | pc2bytes6[(left >>> 4) & 0xF])
      const righttmp = (
        pc2bytes7[right >>> 28] | pc2bytes8[(right >>> 24) & 0xF]
        | pc2bytes9[(right >>> 20) & 0xF] | pc2bytes10[(right >>> 16) & 0xF]
        | pc2bytes11[(right >>> 12) & 0xF] | pc2bytes12[(right >>> 8) & 0xF]
        | pc2bytes13[(right >>> 4) & 0xF])
      tmp = ((righttmp >>> 16) ^ lefttmp) & 0x0000FFFF
      keys[n++] = lefttmp ^ tmp
      keys[n++] = righttmp ^ (tmp << 16)
    }
  }

  return keys
}

/**
 * Updates a single block using DES. The update will either
 * encrypt or decrypt the block.
 *
 * @param keys the expanded keys.
 * @param input the input block buffer.
 * @param output the output block buffer.
 * @param decrypt true to decrypt the block, false to encrypt it.
 */
function _updateBlock(keys: number[], input: ByteStringBuffer, output: ByteStringBuffer, decrypt: boolean): void {
  // convert input buffer to integers
  let left = input.getInt32()
  let right = input.getInt32()

  // initial permutation
  let tmp
  tmp = ((left >>> 4) ^ right) & 0x0F0F0F0F
  right ^= tmp
  left ^= (tmp << 4)
  tmp = ((left >>> 16) ^ right) & 0x0000FFFF
  right ^= tmp
  left ^= (tmp << 16)
  tmp = ((right >>> 2) ^ left) & 0x33333333
  left ^= tmp
  right ^= (tmp << 2)
  tmp = ((right >>> 8) ^ left) & 0x00FF00FF
  left ^= tmp
  right ^= (tmp << 8)
  tmp = ((left >>> 1) ^ right) & 0x55555555
  right ^= tmp
  left ^= (tmp << 1)

  // right needs to be shifted and needs to get last 4 bits of left
  right = ((right << 1) | (right >>> 31))
  tmp = (left ^ right) & 0xAAAAAAAA
  right ^= tmp
  left ^= tmp
  left = ((left << 1) | (left >>> 31))

  for (let i = 0; i < keys.length; i += 4) {
    let keysi = i
    if (decrypt)
      keysi = keys.length - 4 - i

    const work = right ^ keys[keysi]
    const work2 = ((right >>> 4) | (right << 28)) ^ keys[keysi + 1]

    // expand right word into 8 bytes for table lookup
    const t1 = work & 0x3F
    const t2 = ((work >>> 6) | (work << 26)) & 0x3F
    const t3 = ((work >>> 12) | (work << 20)) & 0x3F
    const t4 = ((work >>> 18) | (work << 14)) & 0x3F
    const t5 = ((work >>> 24) | (work << 8)) & 0x3F
    const t6 = ((work >>> 30) | (work << 2)) & 0x3F
    const t7 = work2 & 0x3F
    const t8 = ((work2 >>> 6) | (work2 << 26)) & 0x3F

    // table lookups
    tmp = spfunction1[t1] | spfunction2[t2] | spfunction3[t3] | spfunction4[t4]
      | spfunction5[t5] | spfunction6[t6] | spfunction7[t7] | spfunction8[t8]

    // functions
    const righttemp = left
    left = right
    right = righttemp ^ tmp
  }

  // move left and right by one bit
  left = ((left >>> 1) | (left << 31))
  right = ((right >>> 1) | (right << 31))

  // final permutation
  tmp = (left ^ right) & 0xAAAAAAAA
  left ^= tmp
  right ^= tmp
  right = ((right >>> 1) | (right << 31))
  tmp = ((right >>> 8) ^ left) & 0x00FF00FF
  left ^= tmp
  right ^= (tmp << 8)
  tmp = ((right >>> 2) ^ left) & 0x33333333
  left ^= tmp
  right ^= (tmp << 2)
  tmp = ((left >>> 16) ^ right) & 0x0000FFFF
  right ^= tmp
  left ^= (tmp << 16)
  tmp = ((left >>> 4) ^ right) & 0x0F0F0F0F
  right ^= tmp
  left ^= (tmp << 4)

  // write output
  output.putInt32(right)
  output.putInt32(left)
}

/**
 * Creates a new DES cipher algorithm object.
 *
 * @param name the name of the algorithm.
 * @param mode the mode factory function.
 *
 * @return the DES algorithm object.
 */
export interface DES {
  Algorithm: typeof DESAlgorithm
  createCipher: typeof createCipher
  createEncryptionCipher: typeof createEncryptionCipher
  createDecryptionCipher: typeof createDecryptionCipher
  createKeys: typeof _createKeys
  updateBlock: typeof _updateBlock
}

export function createEncryptionCipher(key: string, bits: string | Buffer): BlockCipher {
  return createCipher(key, bits)
}

function createDecryptionCipher(key: string, bits: string | Buffer): BlockCipher {
  return createCipher(key, bits)
}

export const des: DES = {
  Algorithm: DESAlgorithm,
  createCipher,
  createEncryptionCipher,
  createDecryptionCipher,
  createKeys: _createKeys,
  updateBlock: _updateBlock,
}
