/**
 * Type definitions for the BigInteger library
 *
 * This file contains interfaces used by the BigInteger implementation.
 * Note that there's a circular dependency between this file and jsbn.ts:
 * - The interfaces here reference the BigInteger class
 * - The BigInteger class in jsbn.ts uses these interfaces
 *
 * To resolve this, we import BigInteger at the end of this file after
 * defining all interfaces. This works because TypeScript's type system
 * allows forward references in type definitions.
 */

/**
 * Interface for reduction algorithms used in modular arithmetic
 *
 * The library implements several reduction algorithms:
 * - Classic: Simple modular reduction
 * - Montgomery: Efficient for repeated modular operations
 * - Barrett: Another efficient algorithm for repeated modular operations
 */
export interface IReducer {
  /**
   * Converts a BigInteger to the Montgomery domain
   */
  convert: (x: BigInteger) => BigInteger;

  /**
   * Converts a BigInteger back from the Montgomery domain
   */
  revert: (x: BigInteger) => BigInteger;

  /**
   * Reduces a BigInteger modulo m in-place
   */
  reduce: (x: BigInteger) => void;

  /**
   * Multiplies two BigIntegers and reduces the result modulo m
   */
  mulTo: (x: BigInteger, y: BigInteger, r: BigInteger) => void;

  /**
   * Squares a BigInteger and reduces the result modulo m
   */
  sqrTo: (x: BigInteger, r: BigInteger) => void;
}

/**
 * Interface for pseudo-random number generators
 *
 * Used for generating random BigIntegers and for cryptographic operations.
 * The library provides a SecureRandom implementation that uses the browser's
 * crypto.getRandomValues when available, with a fallback to Math.random.
 */
export interface IPRNG {
  /**
   * Fills an array with random bytes
   * @param x The array to fill with random bytes
   */
  nextBytes: (x: number[] | Uint8Array) => void;
}

/**
 * Import the BigInteger class to avoid circular dependencies
 * This import is placed at the end of the file to allow the interfaces
 * above to reference BigInteger before it's fully defined.
 */
import { BigInteger } from './jsbn';
