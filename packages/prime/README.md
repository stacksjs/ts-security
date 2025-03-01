<p align="center"><img src="../../.github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
<!-- [![npm downloads][npm-downloads-src]][npm-downloads-href] -->
<!-- [![Codecov][codecov-src]][codecov-href] -->

# ts-prime-gen

> A TypeScript implementation of probabilistic prime number generation with a focus on performance and security.

## Features

- 🔢 **Probabilistic Prime Generation** _Generate probable prime numbers of any bit length_
- 🧮 **Miller-Rabin Testing** _Uses the Miller-Rabin primality test for efficient prime verification_
- 🧵 **Web Worker Support** _Optional multi-threaded prime generation for improved performance_
- ⏱️ **Non-Blocking Operation** _Configurable time slicing to prevent UI blocking_
- 🔄 **Customizable PRNG** _Support for custom cryptographically secure random number generators_
- 🛡️ **Type Safety** _Full TypeScript support with comprehensive type definitions_
- 🔍 **Configurable Testing** _Adjustable number of primality tests based on security requirements_
- 🚀 **Performance Optimized** _Efficient algorithms for generating large prime numbers_

## Install

```bash
# bun
bun install ts-prime-gen

# npm
npm install ts-prime-gen

# pnpm
pnpm install ts-prime-gen
```

## Get Started

After installing the package, you can import and use the prime number generation functions:

```ts
import { prime } from 'ts-prime-gen'

// Generate a 1024-bit probable prime
prime.generateProbablePrime(1024, {}, (err, num) => {
  if (err) {
    console.error('Error generating prime:', err)
    return
  }

  console.log('Generated prime:', num.toString())
  console.log('Bit length:', num.bitLength())
  console.log('Is probably prime:', num.isProbablePrime(10))
})

// With custom options
const options = {
  algorithm: 'PRIMEINC',
  maxBlockTime: 10, // ms to allow blocking before yielding
  millerRabinTests: 15, // number of primality tests
  workers: 2, // number of web workers to use (if supported)
  workLoad: 100 // work units per worker
}

prime.generateProbablePrime(2048, options, (err, num) => {
  if (err) {
    console.error('Error generating prime:', err)
    return
  }

  console.log('Generated 2048-bit prime:', num.toString())
})

// With custom PRNG
const customPRNG = {
  getBytesSync: (length) => {
    // Your secure random byte generation logic here
    // Must return a string of length 'length'
    return secureRandomString(length)
  }
}

prime.generateProbablePrime(512, { prng: customPRNG }, (err, num) => {
  if (err) {
    console.error('Error generating prime:', err)
    return
  }

  console.log('Generated prime with custom PRNG:', num.toString())
})
```

## API Reference

### Prime Generation

```ts
function generateProbablePrime(
  bits: number,
  options: PrimeOptions,
  callback: (err: Error | null, num?: BigInteger) => void
): void
```

Generates a random probable prime with the specified number of bits.

#### Parameters

- `bits`: The number of bits for the prime number.
- `options`: Configuration options for prime generation.
- `callback`: Function called with the generated prime or an error.

#### PrimeOptions

```ts
interface PrimeOptions {
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
```

- `algorithm`: The algorithm to use (default: 'PRIMEINC').
- `prng`: A custom crypto-secure pseudo-random number generator.
- `maxBlockTime`: Maximum time (ms) to block the main thread (default: 10ms).
- `millerRabinTests`: Number of Miller-Rabin tests to perform.
- `workers`: Number of web workers to use (-1 for CPU cores - 1).
- `workLoad`: Number of potential primes for each worker to check.
- `workerScript`: Path to the worker script.

### Miller-Rabin Tests

The number of Miller-Rabin tests is automatically determined based on the bit size to achieve an error probability of (1/2)^80:

| Bit Size | Tests |
|----------|-------|
| ≤ 100    | 27    |
| ≤ 150    | 18    |
| ≤ 200    | 15    |
| ≤ 250    | 12    |
| ≤ 300    | 9     |
| ≤ 350    | 8     |
| ≤ 400    | 7     |
| ≤ 500    | 6     |
| ≤ 600    | 5     |
| ≤ 800    | 4     |
| ≤ 1250   | 3     |
| > 1250   | 2     |

## Testing

```bash
bun test
```

## Changelog

Please see our [releases](https://github.com/stacksjs/ts-security/releases) page for more information on what has changed recently.

## Contributing

Please review the [Contributing Guide](https://github.com/stacksjs/contributing) for details.

## Community

For help, discussion about best practices, or any other conversation that would benefit from being searchable:

[Discussions on GitHub](https://github.com/stacksjs/stacks/discussions)

For casual chit-chat with others using this package:

[Join the Stacks Discord Server](https://discord.gg/stacksjs)

## Postcardware

"Software that is free, but hopes for a postcard." We love receiving postcards from around the world showing where `ts-prime-gen` is being used! We showcase them on our website too.

Our address: Stacks.js, 12665 Village Ln #2306, Playa Vista, CA 90094, United States 🌎

## Sponsors

We would like to extend our thanks to the following sponsors for funding Stacks development. If you are interested in becoming a sponsor, please reach out to us.

- [JetBrains](https://www.jetbrains.com/)
- [The Solana Foundation](https://solana.com/)

## Credits

- [Dave Longley](https://github.com/dlongley)
- [node-forge](https://github.com/digitalbazaar/forge)
- [Chris Breuer](https://github.com/chrisbbreuer)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [LICENSE](https://github.com/stacksjs/stacks/tree/main/LICENSE.md) for more information.

Made with 💙

<!-- Badges -->
[npm-version-src]: https://img.shields.io/npm/v/@stacksjs/ts-prime-gen?style=flat-square
[npm-version-href]: https://npmjs.com/package/@stacksjs/ts-prime-gen
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-security/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-security/actions?query=workflow%3Aci

<!-- [codecov-src]: https://img.shields.io/codecov/c/gh/stacksjs/ts-prime-gen/main?style=flat-square
[codecov-href]: https://codecov.io/gh/stacksjs/ts-prime-gen -->
