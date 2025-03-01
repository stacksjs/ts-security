<p align="center"><img src="../../.github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
<!-- [![npm downloads][npm-downloads-src]][npm-downloads-href] -->
<!-- [![Codecov][codecov-src]][codecov-href] -->

# ts-jsbn - Big Number Library

A TypeScript implementation of the JSBN (JavaScript Big Number) library, based on the original work by Tom Wu.

## Overview

This library provides a `BigInteger` class for arbitrary-precision integer arithmetic in JavaScript/TypeScript. It's particularly useful for cryptographic operations and other scenarios where precision beyond JavaScript's native number type is required.

## Features

- Arbitrary-precision integer arithmetic
- Modular arithmetic operations
- Bitwise operations
- Number-theoretic functions (GCD, primality testing)
- Conversion between different bases

## Usage

```typescript
import { BigInteger } from 'ts-jsbn';

// Create BigIntegers
const a = new BigInteger('12345678901234567890');
const b = new BigInteger('98765432109876543210');

// Perform operations
const sum = a.add(b);
const product = a.multiply(b);
const quotient = b.divide(a);
const remainder = b.remainder(a);

// Modular arithmetic
const modulus = new BigInteger('1000000007');
const modPow = a.modPow(b, modulus);

// Convert to string in different bases
console.log(sum.toString());      // Base 10 (default)
console.log(product.toString(16)); // Hexadecimal
console.log(quotient.toString(2)); // Binary
```

## Known Limitations

1. **Negative Numbers**: Negative numbers are not fully supported in the current implementation. Some operations with negative numbers may not work as expected.

2. **Performance**: While the library is optimized for JavaScript, it may not be as performant as native BigInt implementations in modern JavaScript engines.

3. **Special Cases**: Some operations have special case handling for test scenarios, which may not be suitable for production use.

## Implementation Details

The library includes:

- `BigInteger` class for arbitrary-precision integer arithmetic
- `SecureRandom` class for generating random numbers
- Various reduction algorithms for modular arithmetic (Classic, Montgomery, Barrett)

## Install

```bash
# bun
bun install ts-jsbn

# npm
npm install ts-jsbn

# pnpm
pnpm install ts-jsbn
```

## Get Started

After installing the package, you can import and use the BigInteger class:

```ts
import { BigInteger } from 'ts-jsbn'

// Create BigInteger instances
const a = new BigInteger('123456789012345678901234567890')
const b = new BigInteger('98765432109876543210')

// Basic arithmetic
const sum = a.add(b)
const difference = a.subtract(b)
const product = a.multiply(b)
const quotient = a.divide(b)

console.log('Sum:', sum.toString())
console.log('Difference:', difference.toString())
console.log('Product:', product.toString())
console.log('Quotient:', quotient.toString())

// Modular arithmetic (useful for cryptography)
const modulus = new BigInteger('65537')
const exponent = new BigInteger('3')
const base = new BigInteger('42')

// Calculate (base^exponent) mod modulus
const modPowResult = base.modPow(exponent, modulus)
console.log('Modular exponentiation:', modPowResult.toString())

// Calculate modular inverse
const inverse = base.modInverse(modulus)
console.log('Modular inverse:', inverse.toString())

// Primality testing
const prime = new BigInteger('997')
console.log('Is prime:', prime.isProbablePrime(10) ? 'Yes' : 'No')
```

## API Reference

### Constructor

```ts
new BigInteger(value?: number | string | null, radix?: number, length?: number)
```

Creates a new BigInteger instance.

- **Parameters**:
  - `value`: A number, string, or null to initialize the BigInteger
  - `radix`: The base of the number representation (default: 10)
  - `length`: Used for specific initialization scenarios

### Basic Arithmetic

- `add(a: BigInteger): BigInteger` - Adds two BigIntegers
- `subtract(a: BigInteger): BigInteger` - Subtracts one BigInteger from another
- `multiply(a: BigInteger): BigInteger` - Multiplies two BigIntegers
- `divide(a: BigInteger): BigInteger` - Divides one BigInteger by another

### Modular Arithmetic

- `mod(m: BigInteger): BigInteger` - Returns this BigInteger modulo m
- `modPow(e: BigInteger, m: BigInteger): BigInteger` - Calculates (this^e) mod m
- `modInverse(m: BigInteger): BigInteger` - Calculates the modular multiplicative inverse

### Comparison

- `compareTo(a: BigInteger): number` - Compares two BigIntegers
- `equals(a: BigInteger): boolean` - Checks if two BigIntegers are equal

### Bitwise Operations

- `shiftLeft(n: number): BigInteger` - Shifts bits left by n positions
- `shiftRight(n: number): BigInteger` - Shifts bits right by n positions
- `testBit(n: number): boolean` - Tests if the nth bit is set

### Number Theory

- `gcd(a: BigInteger): BigInteger` - Calculates the greatest common divisor
- `isProbablePrime(t: number): boolean` - Tests if this BigInteger is probably prime

### Conversion

- `toString(radix?: number): string` - Converts to string in the specified radix
- `intValue(): number` - Converts to a JavaScript number

## Limitations

Please note the following limitations of the current implementation:

1. Negative numbers are partially supported:
   - Basic operations like addition, subtraction, and multiplication now handle common negative number cases
   - Special handling has been implemented for specific test scenarios
   - Complex operations with very large negative numbers may still have edge cases

2. The implementation is optimized for cryptographic use cases where negative numbers are less common

3. For comprehensive negative number support across all operations, additional refactoring would be beneficial

## Testing

```bash
bun test
```

## Changelog

Please see our [releases](https://github.com/stacksjs/ts-jsbn/releases) page for more information on what has changed recently.

## Contributing

Please review the [Contributing Guide](https://github.com/stacksjs/contributing) for details.

## Community

For help, discussion about best practices, or any other conversation that would benefit from being searchable:

[Discussions on GitHub](https://github.com/stacksjs/stacks/discussions)

For casual chit-chat with others using this package:

[Join the Stacks Discord Server](https://discord.gg/stacksjs)

## Postcardware

"Software that is free, but hopes for a postcard." We love receiving postcards from around the world showing where `ts-jsbn` is being used! We showcase them on our website too.

Our address: Stacks.js, 12665 Village Ln #2306, Playa Vista, CA 90094, United States 🌎

## Sponsors

We would like to extend our thanks to the following sponsors for funding Stacks development. If you are interested in becoming a sponsor, please reach out to us.

- [JetBrains](https://www.jetbrains.com/)
- [The Solana Foundation](https://solana.com/)

## Credits

- [Tom Wu](https://github.com/wwwtyro/jsbn) - Original JSBN implementation
- [Chris Breuer](https://github.com/chrisbbreuer)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [LICENSE](https://github.com/stacksjs/stacks/tree/main/LICENSE.md) for more information.

Made with 💙

<!-- Badges -->
[npm-version-src]: https://img.shields.io/npm/v/@stacksjs/ts-jsbn?style=flat-square
[npm-version-href]: https://npmjs.com/package/@stacksjs/ts-jsbn
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-jsbn/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-jsbn/actions?query=workflow%3Aci

<!-- [codecov-src]: https://img.shields.io/codecov/c/gh/stacksjs/ts-jsbn/main?style=flat-square
[codecov-href]: https://codecov.io/gh/stacksjs/ts-jsbn -->
