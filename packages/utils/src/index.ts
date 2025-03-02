export * from './random'
export * from './buffer'
import { ByteStringBuffer, createBuffer } from './buffer'

export const isServer: boolean = !!(typeof process !== 'undefined' && process.versions && (process.versions.node || process.versions.bun))

// Define util object to fix linter errors
const util: any = {}

// base64 characters, reverse mapping
const _base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
const _base64Idx = [
  /* 43 -43 = 0 */
  /* '+',  1,  2,  3,'/' */
  62,
  -1,
  -1,
  -1,
  63,

  /* '0','1','2','3','4','5','6','7','8','9' */
  52,
  53,
  54,
  55,
  56,
  57,
  58,
  59,
  60,
  61,

  /* 15, 16, 17,'=', 19, 20, 21 */
  -1,
  -1,
  -1,
  64,
  -1,
  -1,
  -1,

  /* 65 - 43 = 22 */
  /* 'A','B','C','D','E','F','G','H','I','J','K','L','M', */
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,

  /* 'N','O','P','Q','R','S','T','U','V','W','X','Y','Z' */
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,

  /* 91 - 43 = 48 */
  /* 48, 49, 50, 51, 52, 53 */
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,

  /* 97 - 43 = 54 */
  /* 'a','b','c','d','e','f','g','h','i','j','k','l','m' */
  26,
  27,
  28,
  29,
  30,
  31,
  32,
  33,
  34,
  35,
  36,
  37,
  38,

  /* 'n','o','p','q','r','s','t','u','v','w','x','y','z' */
  39,
  40,
  41,
  42,
  43,
  44,
  45,
  46,
  47,
  48,
  49,
  50,
  51,
]

export function fillString(char: string, count: number): string {
  let s = ''
  while (count > 0) {
    if (count & 1) {
      s += char
    }
    count >>>= 1
    if (count > 0) {
      char += char
    }
  }
  return s
}

export function encodeUtf8(str: string): string {
  return unescape(encodeURIComponent(str))
}

function _checkBitsParam(n: number): void {
  if (!(n <= 32 && n > 0 && n % 8 === 0)) {
    throw new Error('Number of bits must be 8, 16, 24, or 32')
  }
}

/**
 * Base64 encodes a 'binary' encoded string of bytes.
 *
 * @param input the binary encoded string of bytes to base64-encode.
 * @param maxline the maximum number of encoded characters per line to use, defaults to none.
 *
 * @return the base64-encoded output.
 */
export function encode64(input: string, maxline?: number): string {
  let line = ''
  let output = ''
  let chr1, chr2, chr3
  let i = 0

  while (i < input.length) {
    chr1 = input.charCodeAt(i++)
    chr2 = input.charCodeAt(i++)
    chr3 = input.charCodeAt(i++)

    // encode 4 character group
    line += _base64.charAt(chr1 >> 2)
    line += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4))
    if (Number.isNaN(chr2)) {
      line += '=='
    }
    else {
      line += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6))
      line += Number.isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63)
    }

    if (maxline && line.length > maxline) {
      output += `${line.substring(0, maxline)}\r\n`
      line = line.substring(maxline)
    }
  }

  output += line

  return output
}

/**
 * Base64 decodes a string into a 'binary' encoded string of bytes.
 *
 * @param input the base64-encoded input.
 *
 * @return the binary encoded string.
 */
export function decode64(input: string): string {
  // remove all non-base64 characters
  input = input.replace(/[^A-Z0-9+/=]/gi, '')

  let output = ''
  let enc1, enc2, enc3, enc4
  let i = 0

  while (i < input.length) {
    enc1 = _base64Idx[input.charCodeAt(i++) - 43]
    enc2 = _base64Idx[input.charCodeAt(i++) - 43]
    enc3 = _base64Idx[input.charCodeAt(i++) - 43]
    enc4 = _base64Idx[input.charCodeAt(i++) - 43]

    output += String.fromCharCode((enc1 << 2) | (enc2 >> 4))
    if (enc3 !== 64) {
      // decoded at least 2 bytes
      output += String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2))
      if (enc4 !== 64) {
        // decoded 3 bytes
        output += String.fromCharCode(((enc3 & 3) << 6) | enc4)
      }
    }
  }

  return output
}

/**
 * Converts a string of bytes to a hexadecimal string.
 *
 * @param bytes the string of bytes to convert.
 *
 * @return the hexadecimal string.
 */
export function bytesToHex(bytes: string): string {
  return createBuffer(bytes).toHex()
}

/**
 * Decodes UTF-8 bytes into a string of characters.
 *
 * @param bytes the UTF-8 bytes to decode.
 *
 * @return the string of characters.
 */
export function decodeUtf8(bytes: string): string {
  return decodeURIComponent(escape(bytes))
}

/**
 * Converts a hex string into a 'binary' encoded string of bytes.
 *
 * @param hex the hexadecimal string to convert.
 *
 * @return the binary-encoded string of bytes.
 */
export function hexToBytes(hex: string): string {
  // TODO: deprecate: "Deprecated. Use util.binary.hex.decode instead."
  let rval = ''
  let i = 0
  if ((hex.length & 1) === 1) {
    // odd number of characters, convert first character alone
    i = 1
    rval += String.fromCharCode(Number.parseInt(hex[0], 16))
  }

  // convert 2 characters (1 byte) at a time
  for (; i < hex.length; i += 2) {
    rval += String.fromCharCode(Number.parseInt(hex.substr(i, 2), 16))
  }

  return rval
}

/**
 * Estimates the number of processes that can be run concurrently. If
 * creating Web Workers, keep in mind that the main JavaScript process needs
 * its own core.
 *
 * @param options the options to use: update true to force an update (not use the cached value).
 * @param callback(err, max) called once the operation completes.
 */
export function estimateCores(options: any, callback: any): void {
  if (typeof options === 'function') {
    callback = options
    options = {}
  }

  options = options || {}

  if ('cores' in util && options?.update !== true)
    return callback(null, util.cores)

  if (typeof navigator !== 'undefined'
    && 'hardwareConcurrency' in navigator
    && navigator.hardwareConcurrency > 0) {
    util.cores = navigator.hardwareConcurrency
    return callback(null, util.cores)
  }

  if (typeof Worker === 'undefined') {
    // workers not available
    util.cores = 1
    return callback(null, util.cores)
  }

  if (typeof Blob === 'undefined') {
    // can't estimate, default to 2
    util.cores = 2
    return callback(null, util.cores)
  }

  // create worker concurrency estimation code as blob
  const blobUrl = URL.createObjectURL(new Blob(['(', function () {
    // @ts-ignore
    self.addEventListener('message', (e: any) => {
      // run worker for 4 ms
      const st = Date.now()
      const et = st + 4
      while (Date.now() < et);
      self.postMessage({ st, et })
    })
  }.toString(), ')()'], { type: 'application/javascript' }))

  // take 5 samples using 16 workers
  sample([], 5, 16)

  function sample(max: number[], samples: number, numWorkers: number) {
    if (samples === 0) {
      // get overlap average
      const avg = Math.floor(max.reduce((acc: number, x: number) => acc + x, 0) / max.length)
      util.cores = Math.max(1, avg)
      URL.revokeObjectURL(blobUrl)
      return callback(null, util.cores)
    }

    map(numWorkers, (err: Error | null, results: any[]) => {
      max.push(reduce(numWorkers, results))
      sample(max, samples - 1, numWorkers)
    })
  }

  function map(numWorkers: number, callback: (err: Error | null, results: any[]) => void) {
    const workers: Worker[] = []
    const results: any[] = []

    for (let i = 0; i < numWorkers; ++i) {
      const worker = new Worker(blobUrl)
      workers.push(worker)
      worker.addEventListener('message', (e: MessageEvent<any>) => {
        results.push(e.data)
        if (results.length === numWorkers) {
          for (let i = 0; i < numWorkers; ++i) {
            workers[i].terminate()
          }
          callback(null, results)
        }
      })
      worker.postMessage(i)
    }
  }

  function reduce(numWorkers: number, results: any[]) {
    // find overlapping time windows
    const overlaps: number[] = []
    for (let n = 0; n < numWorkers; ++n) {
      const r1 = results[n]
      for (let i = 0; i < numWorkers; ++i) {
        if (n === i) {
          continue
        }
        const r2 = results[i]
        if ((r1.st > r2.st && r1.st < r2.et)
          || (r2.st > r1.st && r2.st < r1.et)) {
          overlaps.push(i)
        }
      }
    }
    return overlaps.length
  }
}

export interface Utils {
  encodeUtf8: (bytes: string) => string
  decodeUtf8: (bytes: string) => string
  encode64: (input: string, maxline?: number) => string
  decode64: (input: string) => string
  bytesToHex: (bytes: string) => string
  createBuffer: (b?: string | ArrayBuffer | Uint8Array) => ByteStringBuffer
  fillString: (char: string, count: number) => string
  ByteStringBuffer: typeof ByteStringBuffer
  hexToBytes: (hex: string) => string
  estimateCores: (options: any, callback: any) => void
}

export const utils: Utils = {
  encodeUtf8,
  decodeUtf8,
  encode64,
  decode64,
  bytesToHex,
  createBuffer,
  fillString,
  ByteStringBuffer,
  hexToBytes,
  estimateCores,
}
