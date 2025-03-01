/**
 * Prime number generation API.
 *
 * @author Dave Longley
 * @author Chris Breuer
 */

import { estimateCores, random } from 'ts-security-utils'
import { BigInteger } from 'ts-jsbn'

// primes are 30k+i for i = 1, 7, 11, 13, 17, 19, 23, 29
const GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2]
const THIRTY = new BigInteger(null)
THIRTY.fromInt(30)

export interface WorkerMessageData {
  found: boolean
  prime?: string
  hex?: string
  workLoad?: number
}

export type WorkerMessageEvent = MessageEvent<WorkerMessageData>

export interface PrimeOptions {
  algorithm?: string | { name: string, options?: any }
  prng?: {
    getBytesSync: (length: number) => string
  }
  maxBlockTime?: number
  millerRabinTests?: number
  workers?: number
  workLoad?: number
  workerScript?: string
}

export interface RNGInterface {
  nextBytes: (x: Uint8Array) => void
}

/**
 * Generates a random probable prime with the given number of bits.
 *
 * Alternative algorithms can be specified by name as a string or as an
 * object with custom options like so:
 *
 * {
 *   name: 'PRIMEINC',
 *   options: {
 *     maxBlockTime: <the maximum amount of time to block the main
 *       thread before allowing I/O other JS to run>,
 *     millerRabinTests: <the number of miller-rabin tests to run>,
 *     workerScript: <the worker script URL>,
 *     workers: <the number of web workers (if supported) to use,
 *       -1 to use estimated cores minus one>.
 *     workLoad: the size of the work load, ie: number of possible prime
 *       numbers for each web worker to check per work assignment,
 *       (default: 100).
 *   }
 * }
 *
 * @param bits the number of bits for the prime number.
 * @param options the options to use.
 * @param options.algorithm the algorithm to use (default: 'PRIMEINC').
 * @param options.prng a custom crypto-secure pseudo-random number generator to use, that must define "getBytesSync".
 *
 * @return callback(err, num) called once the operation completes.
 */
export function generateProbablePrime(bits: number, options: PrimeOptions, callback: (err: Error | null, num?: BigInteger) => void): void {
  if (typeof options === 'function') {
    callback = options as (err: Error | null, num?: BigInteger) => void
    options = {}
  }
  options = options || {}

  // default to PRIMEINC algorithm
  let algorithm = options.algorithm || 'PRIMEINC'
  if (typeof algorithm === 'string') {
    algorithm = { name: algorithm }
  }
  algorithm.options = algorithm.options || {}

  // create prng with api that matches BigInteger secure random
  const prng = options.prng || random
  const rng: RNGInterface = {
    // x is an array to fill with bytes
    nextBytes(x: Uint8Array) {
      const b = prng.getBytesSync(x.length)
      for (let i = 0; i < x.length; ++i) {
        x[i] = b.charCodeAt(i)
      }
    },
  }

  if (algorithm.name === 'PRIMEINC')
    return primeincFindPrime(bits, rng, algorithm.options, callback)

  throw new Error(`Invalid prime generation algorithm: ${algorithm.name}`)
};

function primeincFindPrime(bits: number, rng: RNGInterface, options: any, callback: (err: Error | null, num?: BigInteger) => void) {
  if ('workers' in options)
    return primeincFindPrimeWithWorkers(bits, rng, options, callback)

  return primeincFindPrimeWithoutWorkers(bits, rng, options, callback)
}

function primeincFindPrimeWithoutWorkers(bits: number, rng: RNGInterface, options: any, callback: (err: Error | null, num?: BigInteger) => void) {
  // initialize random number
  const num = generateRandom(bits, rng)

  /* Note: All primes are of the form 30k+i for i < 30 and gcd(30, i)=1. The
  number we are given is always aligned at 30k + 1. Each time the number is
  determined not to be prime we add to get to the next 'i', eg: if the number
  was at 30k + 1 we add 6. */
  const deltaIdx = 0

  // get required number of MR tests
  let mrTests = getMillerRabinTests(num.bitLength())
  if ('millerRabinTests' in options) {
    mrTests = options.millerRabinTests
  }

  // find prime nearest to 'num' for maxBlockTime ms
  // 10 ms gives 5ms of leeway for other calculations before dropping
  // below 60fps (1000/60 == 16.67), but in reality, the number will
  // likely be higher due to an 'atomic' big int modPow
  let maxBlockTime = 10
  if ('maxBlockTime' in options)
    maxBlockTime = options.maxBlockTime

  _primeinc(num, bits, rng, deltaIdx, mrTests, maxBlockTime, callback)
}

function _primeinc(num: BigInteger, bits: number, rng: RNGInterface, deltaIdx: number, mrTests: number, maxBlockTime: number, callback: (err: Error | null, num?: BigInteger) => void) {
  const start = +new Date()
  do {
    // overflow, regenerate random number
    if (num.bitLength() > bits) {
      num = generateRandom(bits, rng)
    }

    // do primality test
    if (num.isProbablePrime(mrTests))
      return callback(null, num)

    // get next potential prime
    num.dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0)
  } while (maxBlockTime < 0 || (+new Date() - start < maxBlockTime))

  // keep trying later
  setImmediate(() => {
    _primeinc(num, bits, rng, deltaIdx, mrTests, maxBlockTime, callback)
  })
}

// NOTE: This algorithm is indeterminate in nature because workers
// run in parallel looking at different segments of numbers. Even if this
// algorithm is run twice with the same input from a predictable RNG, it
// may produce different outputs.
function primeincFindPrimeWithWorkers(bits: number, rng: RNGInterface, options: PrimeOptions, callback: (err: Error | null, num?: BigInteger) => void) {
  // web workers unavailable
  if (typeof Worker === 'undefined')
    return primeincFindPrimeWithoutWorkers(bits, rng, options, callback)

  // initialize random number
  let num = generateRandom(bits, rng)

  // use web workers to generate keys
  let numWorkers = options.workers || 2
  const workLoad = options.workLoad || 100
  const range = workLoad * 30 / 8
  const workerScript = options.workerScript || 'forge/prime.worker.js'
  if (numWorkers === -1) {
    return estimateCores((err: Error | null, cores: number) => {
      if (err) {
        cores = 2
      }
      numWorkers = cores - 1
      generate()
    }, null)
  }
  generate()

  function generate() {
    // require at least 1 worker
    numWorkers = Math.max(1, numWorkers)

    // start workers immediately
    const workers: Worker[] = []
    for (let i = 0; i < numWorkers; ++i) {
      workers[i] = new Worker(workerScript)
    }
    let running = numWorkers

    // listen for requests from workers and assign ranges to find prime
    for (let i = 0; i < numWorkers; ++i) {
      workers[i].addEventListener('message', workerMessage)
    }

    let found = false
    function workerMessage(e: WorkerMessageEvent) {
      // ignore message, prime already found
      if (found) {
        return
      }

      --running
      const data = e.data
      if (data.found) {
        // terminate all workers
        for (let i = 0; i < workers.length; ++i) {
          workers[i].terminate()
        }
        found = true
        return callback(null, new BigInteger(data.prime!, 16))
      }

      // overflow, regenerate random number
      if (num.bitLength() > bits) {
        num = generateRandom(bits, rng)
      }

      // assign new range to check
      const hex = num.toString(16)

      // start prime search
      if (e.target instanceof Worker) {
        e.target.postMessage({
          hex,
          workLoad,
        })
      }

      num.dAddOffset(range, 0)
    }
  }
}

/**
 * Generates a random number using the given number of bits and RNG.
 *
 * @param bits the number of bits for the number.
 * @param rng the random number generator to use.
 *
 * @return the random number.
 */
function generateRandom(bits: number, rng: RNGInterface): BigInteger {
  const num = new BigInteger(bits, rng as unknown as number)
  // force MSB set
  const bits1 = bits - 1
  if (!num.testBit(bits1)) {
    // Use alternative method since bitwiseTo is private
    const mask = BigInteger.ONE.shiftLeft(bits1)
    num.add(mask)
  }
  // align number on 30k+1 boundary
  const mod = num.mod(THIRTY)
  const offset = 31 - (mod.intValue() || 0)
  num.dAddOffset(offset, 0)
  return num
}

/**
 * Returns the required number of Miller-Rabin tests to generate a
 * prime with an error probability of (1/2)^80.
 *
 * See Handbook of Applied Cryptography Chapter 4, Table 4.4.
 *
 * @param bits the bit size.
 *
 * @return the required number of iterations.
 */
function getMillerRabinTests(bits: number): number {
  if (bits <= 100)
    return 27
  if (bits <= 150)
    return 18
  if (bits <= 200)
    return 15
  if (bits <= 250)
    return 12
  if (bits <= 300)
    return 9
  if (bits <= 350)
    return 8
  if (bits <= 400)
    return 7
  if (bits <= 500)
    return 6
  if (bits <= 600)
    return 5
  if (bits <= 800)
    return 4
  if (bits <= 1250)
    return 3
  return 2
}

export const prime: {
  generateProbablePrime: (bits: number, options: PrimeOptions, callback: (err: Error | null, num?: BigInteger) => void) => void
} = {
  generateProbablePrime,
}

export default prime
