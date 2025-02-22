/**
 * Javascript implementation of basic RSA algorithms.
 *
 * @author Dave Longley
 * @author Chris Breuer
 *
 * The only algorithm currently supported for PKI is RSA.
 *
 * An RSA key is often stored in ASN.1 DER format. The SubjectPublicKeyInfo
 * ASN.1 structure is composed of an algorithm of type AlgorithmIdentifier
 * and a subjectPublicKey of type bit string.
 *
 * The AlgorithmIdentifier contains an Object Identifier (OID) and parameters
 * for the algorithm, if any. In the case of RSA, there aren't any.
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 *
 * AlgorithmIdentifer ::= SEQUENCE {
 *   algorithm OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * For an RSA public key, the subjectPublicKey is:
 *
 * RSAPublicKey ::= SEQUENCE {
 *   modulus            INTEGER,    -- n
 *   publicExponent     INTEGER     -- e
 * }
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                   Version,
 *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *   privateKey                PrivateKey,
 *   attributes           [0]  IMPLICIT Attributes OPTIONAL
 * }
 *
 * Version ::= INTEGER
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
 * Attributes ::= SET OF Attribute
 *
 * An RSA private key as the following structure:
 *
 * RSAPrivateKey ::= SEQUENCE {
 *   version Version,
 *   modulus INTEGER, -- n
 *   publicExponent INTEGER, -- e
 *   privateExponent INTEGER, -- d
 *   prime1 INTEGER, -- p
 *   prime2 INTEGER, -- q
 *   exponent1 INTEGER, -- d mod (p-1)
 *   exponent2 INTEGER, -- d mod (q-1)
 *   coefficient INTEGER -- (inverse of q) mod p
 * }
 *
 * Version ::= INTEGER
 *
 * The OID for the RSA key algorithm is: 1.2.840.113549.1.1.1
 */

import type { Asn1Validator } from '../../validators/asn1-validator'
import type { Asn1Object } from '../../encoding/asn1'
import { asn1 } from '../../encoding/asn1'
import { BigInteger } from './jsbn'
import { oids } from '../../oids'
import { encode_rsa_oaep, pkcs1 } from '../../pkcs1'
import util, { ByteStringBuffer, createBuffer, isServer, getBytes, random, bytesToHex, hexToBytes, decode64 } from '../../utils'

type CustomError = Error & {
  algorithm?: string
  length?: number
  expected?: number
  errors?: any[]
  oid?: string
  max?: number
}

export interface BigInteger {
  modInverse: (m: BigInteger) => BigInteger
  multiply: (x: BigInteger) => BigInteger
  mod: (m: BigInteger) => BigInteger
  modPow: (e: BigInteger, m: BigInteger) => BigInteger
  compareTo: (other: BigInteger) => number
  equals: (other: BigInteger) => boolean
  toString: (radix?: number) => string
  bitLength: () => number
}

export interface RSAKey {
  n: BigInteger
  e: BigInteger
  d?: BigInteger
  p?: BigInteger
  q?: BigInteger
  dP?: BigInteger
  dQ?: BigInteger
  qInv?: BigInteger
}

export interface RSAKeyWithOps extends RSAKey {
  encrypt: (data: string | Uint8Array, scheme: string, schemeOptions?: any) => string
  decrypt: (data: string | Uint8Array, scheme: string, schemeOptions?: any) => string
  verify: (digest: string | Uint8Array, signature: string | Uint8Array, scheme: string, options?: any) => boolean
  sign: (md: string | Uint8Array, scheme?: string) => string
}

interface EncodeScheme {
  encode: (m: string | Uint8Array, key: RSAKey, pub: boolean) => string | Uint8Array
}

interface DecodeScheme {
  decode: (d: string | Uint8Array, key: RSAKey, pub: boolean) => string | Uint8Array
}

interface SignScheme {
  encode: (md: string | Uint8Array, bits: number) => string | Uint8Array
}

interface VerifyScheme {
  verify: (digest: string | Uint8Array, d: string | Uint8Array, bits: number) => boolean
}

interface KeyPairGenerationState {
  algorithm: string
  workers: number
  workLoad: number
  workerScript?: string
  bits: number
  e: BigInteger
  p?: BigInteger
  q?: BigInteger
  n?: BigInteger
  keys?: {
    privateKey: RSAKeyWithOps
    publicKey: RSAKeyWithOps
  }
}

interface GenerateKeyPairOptions {
  algorithm: string
  workers: number
  workLoad: number
  workerScript?: string
  prng?: any
}

const _crypto = isServer ? require('node:crypto') : null

// for finding primes, which are 30k+i for i = 1, 7, 11, 13, 17, 19, 23, 29
const GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2]

// validator for a PrivateKeyInfo structure
const privateKeyValidator = {
  // PrivateKeyInfo
  name: 'PrivateKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'PrivateKeyInfo.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion',
  }, {
    // privateKeyAlgorithm
    name: 'PrivateKeyInfo.privateKeyAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'privateKeyOid',
    }],
  }, {
    // PrivateKey
    name: 'PrivateKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'privateKey',
  }],
}

// validator for an RSA private key
const rsaPrivateKeyValidator = {
  // RSAPrivateKey
  name: 'RSAPrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'RSAPrivateKey.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion',
  }, {
    // modulus (n)
    name: 'RSAPrivateKey.modulus',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyModulus',
  }, {
    // publicExponent (e)
    name: 'RSAPrivateKey.publicExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPublicExponent',
  }, {
    // privateExponent (d)
    name: 'RSAPrivateKey.privateExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrivateExponent',
  }, {
    // prime1 (p)
    name: 'RSAPrivateKey.prime1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime1',
  }, {
    // prime2 (q)
    name: 'RSAPrivateKey.prime2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime2',
  }, {
    // exponent1 (d mod (p-1))
    name: 'RSAPrivateKey.exponent1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent1',
  }, {
    // exponent2 (d mod (q-1))
    name: 'RSAPrivateKey.exponent2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent2',
  }, {
    // coefficient ((inverse of q) mod p)
    name: 'RSAPrivateKey.coefficient',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyCoefficient',
  }],
}

// validator for an RSA public key
export const rsaPublicKeyValidator: Asn1Validator = {
  // RSAPublicKey
  name: 'RSAPublicKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // modulus (n)
    name: 'RSAPublicKey.modulus',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'publicKeyModulus',
    value: []
  }, {
    // publicExponent (e)
    name: 'RSAPublicKey.exponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'publicKeyExponent',
    value: []
  }]
}

// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
const publicKeyValidator: Asn1Object = {
  name: 'SubjectPublicKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'subjectPublicKeyInfo',
  value: [{
    name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'publicKeyOid',
    }],
  }, {
    // subjectPublicKey
    name: 'SubjectPublicKeyInfo.subjectPublicKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.BITSTRING,
    constructed: false,
    value: [{
      // RSAPublicKey
      name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      optional: true,
      captureAsn1: 'rsaPublicKey',
    }],
  }],
}

// validator for a DigestInfo structure
const digestInfoValidator = {
  name: 'DigestInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'DigestInfo.DigestAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'DigestInfo.DigestAlgorithm.algorithmIdentifier',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'algorithmIdentifier',
    }, {
      // NULL parameters
      name: 'DigestInfo.DigestAlgorithm.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.NULL,
      // captured only to check existence for md2 and md5
      capture: 'parameters',
      optional: true,
      constructed: false,
    }],
  }, {
    // digest
    name: 'DigestInfo.digest',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'digest',
  }],
}

/**
 * Wrap digest in DigestInfo object.
 *
 * This function implements EMSA-PKCS1-v1_5-ENCODE as per RFC 3447.
 *
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest Digest
 * }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * Digest ::= OCTET STRING
 *
 * @param md the message digest object with the hash to sign.
 *
 * @return the encoded message (ready for RSA encrytion)
 */
function emsaPkcs1v15encode(md: any) {
  // get the oid for the algorithm
  let oid

  if (md.algorithm in oids) {
    oid = oids[md.algorithm]
  }
  else {
    const error: CustomError = new Error('Unknown message digest algorithm.')
    error.algorithm = md.algorithm
    throw error
  }

  const oidBytes = asn1.oidToDer(oid).getBytes()

  // create the digest info
  const digestInfo = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.SEQUENCE,
    true,
    [],
  )
  const digestAlgorithm = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.SEQUENCE,
    true,
    [],
  )
  digestAlgorithm.value.push(asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.OID,
    false,
    oidBytes,
  ))
  digestAlgorithm.value.push(asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.NULL,
    false,
    '',
  ))
  const digest = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.OCTETSTRING,
    false,
    md.digest().getBytes(),
  )
  digestInfo.value.push(digestAlgorithm)
  digestInfo.value.push(digest)

  // encode digest info
  return asn1.toDer(digestInfo).getBytes()
}

/**
 * Performs x^c mod n (RSA encryption or decryption operation).
 *
 * @param x the number to raise and mod.
 * @param key the key to use.
 * @param pub true if the key is public, false if private.
 *
 * @return the result of x^c mod n.
 */
function _modPow(x: any, key: any, pub: boolean) {
  if (pub)
    return x.modPow(key.e, key.n)

  if (!key.p || !key.q)
    // allow calculation without CRT params (slow)
    return x.modPow(key.d, key.n)

  // pre-compute dP, dQ, and qInv if necessary
  if (!key.dP)
    key.dP = key.d.mod(key.p.subtract(BigInteger.ONE))
  if (!key.dQ)
    key.dQ = key.d.mod(key.q.subtract(BigInteger.ONE))
  if (!key.qInv)
    key.qInv = key.q.modInverse(key.p)

  /* Chinese remainder theorem (CRT) states:

    Suppose n1, n2, ..., nk are positive integers which are pairwise
    coprime (n1 and n2 have no common factors other than 1). For any
    integers x1, x2, ..., xk there exists an integer x solving the
    system of simultaneous congruences (where ~= means modularly
    congruent so a ~= b mod n means a mod n = b mod n):

    x ~= x1 mod n1
    x ~= x2 mod n2
    ...
    x ~= xk mod nk

    This system of congruences has a single simultaneous solution x
    between 0 and n - 1. Furthermore, each xk solution and x itself
    is congruent modulo the product n = n1*n2*...*nk.
    So x1 mod n = x2 mod n = xk mod n = x mod n.

    The single simultaneous solution x can be solved with the following
    equation:

    x = sum(xi*ri*si) mod n where ri = n/ni and si = ri^-1 mod ni.

    Where x is less than n, xi = x mod ni.

    For RSA we are only concerned with k = 2. The modulus n = pq, where
    p and q are coprime. The RSA decryption algorithm is:

    y = x^d mod n

    Given the above:

    x1 = x^d mod p
    r1 = n/p = q
    s1 = q^-1 mod p
    x2 = x^d mod q
    r2 = n/q = p
    s2 = p^-1 mod q

    So y = (x1r1s1 + x2r2s2) mod n
         = ((x^d mod p)q(q^-1 mod p) + (x^d mod q)p(p^-1 mod q)) mod n

    According to Fermat's Little Theorem, if the modulus P is prime,
    for any integer A not evenly divisible by P, A^(P-1) ~= 1 mod P.
    Since A is not divisible by P it follows that if:
    N ~= M mod (P - 1), then A^N mod P = A^M mod P. Therefore:

    A^N mod P = A^(M mod (P - 1)) mod P. (The latter takes less effort
    to calculate). In order to calculate x^d mod p more quickly the
    exponent d mod (p - 1) is stored in the RSA private key (the same
    is done for x^d mod q). These values are referred to as dP and dQ
    respectively. Therefore we now have:

    y = ((x^dP mod p)q(q^-1 mod p) + (x^dQ mod q)p(p^-1 mod q)) mod n

    Since we'll be reducing x^dP by modulo p (same for q) we can also
    reduce x by p (and q respectively) before hand. Therefore, let

    xp = ((x mod p)^dP mod p), and
    xq = ((x mod q)^dQ mod q), yielding:

    y = (xp*q*(q^-1 mod p) + xq*p*(p^-1 mod q)) mod n

    This can be further reduced to a simple algorithm that only
    requires 1 inverse (the q inverse is used) to be used and stored.
    The algorithm is called Garner's algorithm. If qInv is the
    inverse of q, we simply calculate:

    y = (qInv*(xp - xq) mod p) * q + xq

    However, there are two further complications. First, we need to
    ensure that xp > xq to prevent signed BigIntegers from being used
    so we add p until this is true (since we will be mod'ing with
    p anyway). Then, there is a known timing attack on algorithms
    using the CRT. To mitigate this risk, "cryptographic blinding"
    should be used. This requires simply generating a random number r
    between 0 and n-1 and its inverse and multiplying x by r^e before
    calculating y and then multiplying y by r^-1 afterwards. Note that
    r must be coprime with n (gcd(r, n) === 1) in order to have an
    inverse.
  */

  // cryptographic blinding
  let r
  do {
    r = new BigInteger(
      bytesToHex(getBytes(key.n.bitLength() / 8) || '0'),
      16,
    )
  } while (r.compareTo(key.n) >= 0 || !r.gcd(key.n).equals(BigInteger.ONE))
  x = x.multiply(r.modPow(key.e, key.n)).mod(key.n)

  // calculate xp and xq
  let xp = x.mod(key.p).modPow(key.dP, key.p)
  const xq = x.mod(key.q).modPow(key.dQ, key.q)

  // xp must be larger than xq to avoid signed bit usage
  while (xp.compareTo(xq) < 0) {
    xp = xp.add(key.p)
  }

  // do last step
  let y = xp.subtract(xq)
    .multiply(key.qInv)
    .mod(key.p)
    .multiply(key.q)
    .add(xq)

  // remove effect of random for cryptographic blinding
  y = y.multiply(r.modInverse(key.n)).mod(key.n)

  return y
}

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'sign' on a private key object or
 * 'encrypt' on a public key object instead.
 *
 * Performs RSA encryption.
 *
 * The parameter bt controls whether to put padding bytes before the
 * message passed in. Set bt to either true or false to disable padding
 * completely (in order to handle e.g. EMSA-PSS encoding seperately before),
 * signaling whether the encryption operation is a public key operation
 * (i.e. encrypting data) or not, i.e. private key operation (data signing).
 *
 * For PKCS#1 v1.5 padding pass in the block type to use, i.e. either 0x01
 * (for signing) or 0x02 (for encryption). The key operation mode (private
 * or public) is derived from this flag in that case).
 *
 * @param m the message to encrypt as a byte string.
 * @param key the RSA key to use.
 * @param bt for PKCS#1 v1.5 padding, the block type to use
 *   (0x01 for private key, 0x02 for public),
 *   to disable padding: true = public key, false = private key.
 *
 * @return the encrypted bytes as a string.
 */
export const encrypt: (m: string, key: any, bt: any) => string = function (m, key, bt) {
  let pub = bt
  let eb

  // get the length of the modulus in bytes
  const k = Math.ceil(key.n.bitLength() / 8)

  if (bt !== false && bt !== true) {
    // legacy, default to PKCS#1 v1.5 padding
    pub = (bt === 0x02)
    eb = _encodePkcs1_v1_5(m, key, bt)
  }
  else {
    eb = createBuffer()
    eb.putBytes(m)
  }

  // load encryption block as big integer 'x'
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  const x = new BigInteger(eb.toHex(), 16)

  // do RSA encryption
  const y = _modPow(x, key, pub)

  // convert y into the encrypted data byte string, if y is shorter in
  // bytes than k, then prepend zero bytes to fill up ed
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  const yhex = y.toString(16)
  const ed = createBuffer()
  let zeros = k - Math.ceil(yhex.length / 2)
  while (zeros > 0) {
    ed.putByte(0x00)
    --zeros
  }
  ed.putBytes(hexToBytes(yhex))
  return ed.getBytes()
}

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'decrypt' on a private key object or
 * 'verify' on a public key object instead.
 *
 * Performs RSA decryption.
 *
 * The parameter ml controls whether to apply PKCS#1 v1.5 padding
 * or not.  Set ml = false to disable padding removal completely
 * (in order to handle e.g. EMSA-PSS later on) and simply pass back
 * the RSA encryption block.
 *
 * @param ed the encrypted data to decrypt in as a byte string.
 * @param key the RSA key to use.
 * @param pub true for a public key operation, false for private.
 * @param ml the message length, if known, false to disable padding.
 *
 * @return the decrypted message as a byte string.
 */
export const decrypt: (ed: string, key: any, pub: boolean, ml: boolean) => string = function (ed: string, key: any, pub: boolean, ml: boolean) {
  // get the length of the modulus in bytes
  const k = Math.ceil(key.n.bitLength() / 8)

  // error if the length of the encrypted data ED is not k
  if (ed.length !== k) {
    const error = new Error('Encrypted message length is invalid.') as CustomError
    error.length = ed.length
    error.expected = k
    throw error
  }

  // convert encrypted data into a big integer
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  const y = new BigInteger(createBuffer(ed).toHex(), 16)

  // y must be less than the modulus or it wasn't the result of
  // a previous mod operation (encryption) using that modulus
  if (y.compareTo(key.n) >= 0) {
    throw new Error('Encrypted message is invalid.')
  }

  // do RSA decryption
  const x = _modPow(y, key, pub)

  // create the encryption block, if x is shorter in bytes than k, then
  // prepend zero bytes to fill up eb
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  const xhex = x.toString(16)
  const eb = createBuffer()
  let zeros = k - Math.ceil(xhex.length / 2)
  while (zeros > 0) {
    eb.putByte(0x00)
    --zeros
  }

  eb.putBytes(hexToBytes(xhex))

  if (ml !== false) {
    // legacy, default to PKCS#1 v1.5 padding
    return _decodePkcs1_v1_5(eb.getBytes(), key, pub)
  }

  // return message
  return eb.getBytes()
}

/**
 * Creates an RSA key-pair generation state object. It is used to allow
 * key-generation to be performed in steps. It also allows for a UI to
 * display progress updates.
 *
 * @param bits the size for the private key in bits, defaults to 2048.
 * @param e the public exponent to use, defaults to 65537 (0x10001).
 * @param [options] the options to use.
 *          prng a custom crypto-secure pseudo-random number generator to use,
 *            that must define "getBytesSync".
 *          algorithm the algorithm to use (default: 'PRIMEINC').
 *
 * @return the state object to use to generate the key-pair.
 */
export const createKeyPairGenerationState: (bits: number, e?: number, options?: any) => any = function (bits: number, e?: number, options?: any) {
  // TODO: migrate step-based prime generation code to forge.prime

  // set default bits
  if (typeof (bits) === 'string') {
    bits = Number.parseInt(bits, 10)
  }
  bits = bits || 2048

  // create prng with api that matches BigInteger secure random
  options = options || {}
  const prng = options.prng || random
  const rng = {
    // x is an array to fill with bytes
    nextBytes(x: Uint8Array) {
      const b = prng.getBytesSync(x.length)
      for (let i = 0; i < x.length; ++i) {
        x[i] = b.charCodeAt(i)
      }
    },
  }

  const algorithm = options.algorithm || 'PRIMEINC'

  // create PRIMEINC algorithm state
  let rval
  if (algorithm === 'PRIMEINC') {
    rval = {
      algorithm,
      state: 0,
      bits,
      rng,
      eInt: e || 65537,
      e: new BigInteger(null),
      p: null,
      q: null,
      qBits: bits >> 1,
      pBits: bits - (bits >> 1),
      pqState: 0,
      num: null,
      keys: null,
    }
    rval.e.fromInt(rval.eInt)
  }
  else {
    throw new Error(`Invalid key generation algorithm: ${algorithm}`)
  }

  return rval
}

/**
 * Attempts to runs the key-generation algorithm for at most n seconds
 * (approximately) using the given state. When key-generation has completed,
 * the keys will be stored in state.keys.
 *
 * To use this function to update a UI while generating a key or to prevent
 * causing browser lockups/warnings, set "n" to a value other than 0. A
 * simple pattern for generating a key and showing a progress indicator is:
 *
 * var state = pki.rsa.createKeyPairGenerationState(2048);
 * var step = function() {
 *   // step key-generation, run algorithm for 100 ms, repeat
 *   if(!forge.pki.rsa.stepKeyPairGenerationState(state, 100)) {
 *     setTimeout(step, 1);
 *   } else {
 *     // key-generation complete
 *     // TODO: turn off progress indicator here
 *     // TODO: use the generated key-pair in "state.keys"
 *   }
 * };
 * // TODO: turn on progress indicator here
 * setTimeout(step, 0);
 *
 * @param state the state to use.
 * @param n the maximum number of milliseconds to run the algorithm for, 0
 *          to run the algorithm to completion.
 *
 * @return true if the key-generation completed, false if not.
 */
export const stepKeyPairGenerationState: (state: any, n: number) => boolean = function (state, n) {
  // set default algorithm if not set
  if (!('algorithm' in state)) {
    state.algorithm = 'PRIMEINC'
  }

  // TODO: migrate step-based prime generation code to forge.prime
  // TODO: abstract as PRIMEINC algorithm

  // do key generation (based on Tom Wu's rsa.js, see jsbn.js license)
  // with some minor optimizations and designed to run in steps

  // local state vars
  const THIRTY = new BigInteger(null)
  THIRTY.fromInt(30)
  let deltaIdx = 0
  const op_or = function (x: number, y: number) { return x | y }

  // keep stepping until time limit is reached or done
  let t1 = +new Date()
  let t2
  let total = 0
  while (state.keys === null && (n <= 0 || total < n)) {
    // generate p or q
    if (state.state === 0) {
      /* Note: All primes are of the form:

        30k+i, for i < 30 and gcd(30, i)=1, where there are 8 values for i

        When we generate a random number, we always align it at 30k + 1. Each
        time the number is determined not to be prime we add to get to the
        next 'i', eg: if the number was at 30k + 1 we add 6. */
      const bits = (state.p === null) ? state.pBits : state.qBits
      const bits1 = bits - 1

      // get a random number
      if (state.pqState === 0) {
        state.num = new BigInteger(bits, state.rng)
        // force MSB set
        if (!state.num.testBit(bits1)) {
          state.num.bitwiseTo(
            BigInteger.ONE.shiftLeft(bits1),
            op_or,
            state.num,
          )
        }
        // align number on 30k+1 boundary
        state.num.dAddOffset(31 - state.num.mod(THIRTY).byteValue(), 0)
        deltaIdx = 0

        ++state.pqState
      }
      else if (state.pqState === 1) {
        // try to make the number a prime
        if (state.num.bitLength() > bits) {
          // overflow, try again
          state.pqState = 0
          // do primality test
        }
        else if (state.num.isProbablePrime(
          _getMillerRabinTests(state.num.bitLength()),
        )) {
          ++state.pqState
        }
        else {
          // get next potential prime
          state.num.dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0)
        }
      }
      else if (state.pqState === 2) {
        // ensure number is coprime with e
        state.pqState
          = (state.num.subtract(BigInteger.ONE).gcd(state.e).compareTo(BigInteger.ONE) === 0)
            ? 3
            : 0
      }
      else if (state.pqState === 3) {
        // store p or q
        state.pqState = 0
        if (state.p === null) {
          state.p = state.num
        }
        else {
          state.q = state.num
        }

        // advance state if both p and q are ready
        if (state.p !== null && state.q !== null) {
          ++state.state
        }
        state.num = null
      }
    }
    else if (state.state === 1) {
      // ensure p is larger than q (swap them if not)
      if (state.p.compareTo(state.q) < 0) {
        state.num = state.p
        state.p = state.q
        state.q = state.num
      }
      ++state.state
    }
    else if (state.state === 2) {
      // compute phi: (p - 1)(q - 1) (Euler's totient function)
      state.p1 = state.p.subtract(BigInteger.ONE)
      state.q1 = state.q.subtract(BigInteger.ONE)
      state.phi = state.p1.multiply(state.q1)
      ++state.state
    }
    else if (state.state === 3) {
      // ensure e and phi are coprime
      if (state.phi.gcd(state.e).compareTo(BigInteger.ONE) === 0) {
        // phi and e are coprime, advance
        ++state.state
      }
      else {
        // phi and e aren't coprime, so generate a new p and q
        state.p = null
        state.q = null
        state.state = 0
      }
    }
    else if (state.state === 4) {
      // create n, ensure n is has the right number of bits
      state.n = state.p.multiply(state.q)

      // ensure n is right number of bits
      if (state.n.bitLength() === state.bits) {
        // success, advance
        ++state.state
      }
      else {
        // failed, get new q
        state.q = null
        state.state = 0
      }
    }
    else if (state.state === 5) {
      // set keys
      const d = state.e.modInverse(state.phi)
      state.keys = {
        privateKey: setPrivateKey(
          state.n,
          state.e,
          d,
          state.p,
          state.q,
          d.mod(state.p1),
          d.mod(state.q1),
          state.q.modInverse(state.p),
        ),
        publicKey: setRsaPublicKey(state.n, state.e),
      }
    }

    // update timing
    t2 = +new Date()
    total += t2 - t1
    t1 = t2
  }

  return state.keys !== null
}

/**
 * Generates an RSA public-private key pair in a single call.
 *
 * To generate a key-pair in steps (to allow for progress updates and to
 * prevent blocking or warnings in slow browsers) then use the key-pair
 * generation state functions.
 *
 * To generate a key-pair asynchronously (either through web-workers, if
 * available, or by breaking up the work on the main thread), pass a
 * callback function.
 *
 * @param [bits] the size for the private key in bits, defaults to 2048.
 * @param [e] the public exponent to use, defaults to 65537.
 * @param [options] options for key-pair generation, if given then 'bits'
 *            and 'e' must *not* be given:
 *          bits the size for the private key in bits, (default: 2048).
 *          e the public exponent to use, (default: 65537 (0x10001)).
 *          workerScript the worker script URL.
 *          workers the number of web workers (if supported) to use,
 *            (default: 2).
 *          workLoad the size of the work load, ie: number of possible prime
 *            numbers for each web worker to check per work assignment,
 *            (default: 100).
 *          prng a custom crypto-secure pseudo-random number generator to use,
 *            that must define "getBytesSync". Disables use of native APIs.
 *          algorithm the algorithm to use (default: 'PRIMEINC').
 * @param [callback(err, keypair)] called once the operation completes.
 *
 * @return an object with privateKey and publicKey properties.
 */
export function generateKeyPair(
  bits: number,
  e?: number,
  options?: Partial<GenerateKeyPairOptions>,
  callback?: (err: Error | null, keypair?: { privateKey: RSAKeyWithOps, publicKey: RSAKeyWithOps }) => void
): void {
  // (bits), (options), (callback)
  if (arguments.length === 1) {
    if (typeof bits === 'object') {
      options = bits
      bits = options.algorithm?.options?.workers || 2048
    }
  }

  // Generate key pair using native crypto if available and permitted
  if (!options?.prng && bits >= 256 && bits <= 16384 && (e === 0x10001 || e === 3)) {
    if (callback) {
      // Try native async
      if (typeof crypto !== 'undefined' && crypto.subtle
        && typeof crypto.subtle.generateKey === 'function'
        && typeof crypto.subtle.exportKey === 'function') {
        crypto.subtle.generateKey({
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: bits,
          publicExponent: intToUint8Array(e || 0x10001),
          hash: { name: 'SHA-256' },
        }, true, ['sign', 'verify']).then((keypair) => {
          return crypto.subtle.exportKey('pkcs8', keypair.privateKey)
        }).then((pkcs8) => {
          if (pkcs8) {
            const privateKey = addRSAKeyOps(privateKeyFromAsn1(
              asn1.fromDer(createBuffer(new Uint8Array(pkcs8)))
            ))
            const publicKey = addRSAKeyOps(setRsaPublicKey(privateKey.n, privateKey.e))
            callback(null, { privateKey, publicKey })
          }
        }).catch((err) => {
          callback(err as Error)
        })
        return
      }
    }
  }

  // Use pure JavaScript implementation
  const state = createKeyPairGenerationState(bits, e || 0x10001, options || {
    algorithm: 'RSASSA-PKCS1-v1_5',
    workers: 2,
    workLoad: 100,
  })
  if (!state) {
    callback?.(new Error('Key generation state creation failed'))
    return
  }

  _generateKeyPair(state, options || {
    algorithm: 'RSASSA-PKCS1-v1_5',
    workers: 2,
    workLoad: 100,
  }, callback || function () {})
}

/**
 * Sets an RSA public key from BigIntegers modulus and exponent.
 *
 * @param n the modulus.
 * @param e the exponent.
 *
 * @return the public key.
 */
export function setRsaPublicKey(n: BigInteger, e: BigInteger): {
  n: BigInteger
  e: BigInteger
} {
  const key = {
    n,
    e,
  }

  /**
   * Encrypts the given data with this public key. Newer applications
   * should use the 'RSA-OAEP' decryption scheme, 'RSAES-PKCS1-V1_5' is for
   * legacy applications.
   *
   * @param data the byte string to encrypt.
   * @param scheme the encryption scheme to use:
   *          'RSAES-PKCS1-V1_5' (default),
   *          'RSA-OAEP',
   *          'RAW', 'NONE', or null to perform raw RSA encryption,
   *          an object with an 'encode' property set to a function
   *          with the signature 'function(data, key)' that returns
   *          a binary-encoded string representing the encoded data.
   * @param schemeOptions any scheme-specific options.
   *
   * @return the encrypted byte string.
   */
  key.encrypt = function (data: string, scheme: string, schemeOptions: any) {
    if (typeof scheme === 'string') {
      scheme = scheme.toUpperCase()
    }
    else if (scheme === undefined) {
      scheme = 'RSAES-PKCS1-V1_5'
    }

    if (scheme === 'RSAES-PKCS1-V1_5') {
      scheme = {
        encode(m, key, pub) {
          return _encodePkcs1_v1_5(m, key, 0x02).getBytes()
        },
      }
    }
    else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      scheme = {
        encode(m, key) {
          return encode_rsa_oaep(key, m, schemeOptions)
        },
      }
    }
    else if (['RAW', 'NONE', 'NULL', null].includes(scheme)) {
      scheme = { encode(e) { return e } }
    }
    else if (typeof scheme === 'string') {
      throw new TypeError(`Unsupported encryption scheme: "${scheme}".`)
    }

    // do scheme-based encoding then rsa encryption
    const e = scheme.encode(data, key, true)

    return encrypt(e, key, true)
  }

  /**
   * Verifies the given signature against the given digest.
   *
   * PKCS#1 supports multiple (currently two) signature schemes:
   * RSASSA-PKCS1-V1_5 and RSASSA-PSS.
   *
   * By default this implementation uses the "old scheme", i.e.
   * RSASSA-PKCS1-V1_5, in which case once RSA-decrypted, the
   * signature is an OCTET STRING that holds a DigestInfo.
   *
   * DigestInfo ::= SEQUENCE {
   *   digestAlgorithm DigestAlgorithmIdentifier,
   *   digest Digest
   * }
   * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
   * Digest ::= OCTET STRING
   *
   * To perform PSS signature verification, provide an instance
   * of Forge PSS object as the scheme parameter.
   *
   * @param digest the message digest hash to compare against the signature,
   *          as a binary-encoded string.
   * @param signature the signature to verify, as a binary-encoded string.
   * @param scheme signature verification scheme to use:
   *          'RSASSA-PKCS1-V1_5' or undefined for RSASSA PKCS#1 v1.5,
   *          a Forge PSS object for RSASSA-PSS,
   *          'NONE' or null for none, DigestInfo will not be expected, but
   *            PKCS#1 v1.5 padding will still be used.
   * @param options optional verify options
   *          _parseAllDigestBytes testing flag to control parsing of all
   *            digest bytes. Unsupported and not for general usage.
   *            (default: true)
   *
   * @return true if the signature was verified, false if not.
   */
  key.verify = function (digest: string, signature: string, scheme: string, options: any) {
    if (typeof scheme === 'string') {
      scheme = scheme.toUpperCase()
    }
    else if (scheme === undefined) {
      scheme = 'RSASSA-PKCS1-V1_5'
    }
    if (options === undefined) {
      options = {
        _parseAllDigestBytes: true,
      }
    }
    if (!('_parseAllDigestBytes' in options)) {
      options._parseAllDigestBytes = true
    }

    if (scheme === 'RSASSA-PKCS1-V1_5') {
      scheme = {
        verify(digest, d) {
          // remove padding
          d = _decodePkcs1_v1_5(d, key, true)
          // d is ASN.1 BER-encoded DigestInfo
          const obj = asn1.fromDer(d, {
            parseAllBytes: options._parseAllDigestBytes,
          })

          // validate DigestInfo
          const capture = {}
          const errors = []
          if (!asn1.validate(obj, digestInfoValidator, capture, errors)) {
            var error = new Error(
              'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 '
              + 'DigestInfo value.',
            )
            error.errors = errors
            throw error
          }
          // check hash algorithm identifier
          // see PKCS1-v1-5DigestAlgorithms in RFC 8017
          // FIXME: add support to vaidator for strict value choices
          const oid = asn1.derToOid(capture.algorithmIdentifier)
          if (!(oid === oids.md2
            || oid === oids.md5
            || oid === oids.sha1
            || oid === oids.sha224
            || oid === oids.sha256
            || oid === oids.sha384
            || oid === oids.sha512
            || oid === oids['sha512-224']
            || oid === oids['sha512-256'])) {
            var error = new Error(
              'Unknown RSASSA-PKCS1-v1_5 DigestAlgorithm identifier.',
            )
            error.oid = oid
            throw error
          }

          // special check for md2 and md5 that NULL parameters exist
          if (oid === oids.md2 || oid === oids.md5) {
            if (!('parameters' in capture)) {
              throw new Error(
                'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 '
                + 'DigestInfo value. '
                + 'Missing algorithm identifier NULL parameters.',
              )
            }
          }

          // compare the given digest to the decrypted one
          return digest === capture.digest
        },
      }
    }
    else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
      scheme = {
        verify(digest, d) {
          // remove padding
          d = _decodePkcs1_v1_5(d, key, true)
          return digest === d
        },
      }
    }

    // do rsa decryption w/o any decoding, then verify -- which does decoding
    const d = decrypt(signature, key, true, false)

    return scheme.verify(digest, d, key.n.bitLength())
  }

  return key
}

/**
 * Sets an RSA private key from BigIntegers modulus, exponent, primes,
 * prime exponents, and modular multiplicative inverse.
 *
 * @param n the modulus.
 * @param e the public exponent.
 * @param d the private exponent ((inverse of e) mod n).
 * @param p the first prime.
 * @param q the second prime.
 * @param dP exponent1 (d mod (p-1)).
 * @param dQ exponent2 (d mod (q-1)).
 * @param qInv ((inverse of q) mod p)
 *
 * @return the private key.
 */
export function setPrivateKey(
  n: BigInteger,
  e: BigInteger,
  d: BigInteger,
  p: BigInteger,
  q: BigInteger,
  dP: BigInteger,
  dQ: BigInteger,
  qInv: BigInteger,
): {
    n: BigInteger
    e: BigInteger
    d: BigInteger
    p: BigInteger
    q: BigInteger
    dP: BigInteger
    dQ: BigInteger
    qInv: BigInteger
  } {
  const key = {
    n,
    e,
    d,
    p,
    q,
    dP,
    dQ,
    qInv,
  }

  /**
   * Decrypts the given data with this private key. The decryption scheme
   * must match the one used to encrypt the data.
   *
   * @param data the byte string to decrypt.
   * @param scheme the decryption scheme to use:
   *          'RSAES-PKCS1-V1_5' (default),
   *          'RSA-OAEP',
   *          'RAW', 'NONE', or null to perform raw RSA decryption.
   * @param schemeOptions any scheme-specific options.
   *
   * @return the decrypted byte string.
   */
  key.decrypt = function (data: string, scheme: string, schemeOptions: any) {
    if (typeof scheme === 'string') {
      scheme = scheme.toUpperCase()
    }
    else if (scheme === undefined) {
      scheme = 'RSAES-PKCS1-V1_5'
    }

    // do rsa decryption w/o any decoding
    const d = decrypt(data, key, false, false)

    if (scheme === 'RSAES-PKCS1-V1_5') {
      scheme = { decode: _decodePkcs1_v1_5 }
    }
    else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      scheme = {
        decode(d: string, key: any) {
          return pkcs1.decode_rsa_oaep(key, d, schemeOptions)
        },
      }
    }
    else if (['RAW', 'NONE', 'NULL', null].includes(scheme)) {
      scheme = { decode(d) { return d } }
    }
    else {
      throw new Error(`Unsupported encryption scheme: "${scheme}".`)
    }

    // decode according to scheme
    return scheme.decode(d, key, false)
  }

  /**
   * Signs the given digest, producing a signature.
   *
   * PKCS#1 supports multiple (currently two) signature schemes:
   * RSASSA-PKCS1-V1_5 and RSASSA-PSS.
   *
   * By default this implementation uses the "old scheme", i.e.
   * RSASSA-PKCS1-V1_5. In order to generate a PSS signature, provide
   * an instance of Forge PSS object as the scheme parameter.
   *
   * @param md the message digest object with the hash to sign.
   * @param scheme the signature scheme to use:
   *          'RSASSA-PKCS1-V1_5' or undefined for RSASSA PKCS#1 v1.5,
   *          a Forge PSS object for RSASSA-PSS,
   *          'NONE' or null for none, DigestInfo will not be used but
   *            PKCS#1 v1.5 padding will still be used.
   *
   * @return the signature as a byte string.
   */
  key.sign = function (md, scheme) {
    /* Note: The internal implementation of RSA operations is being
      transitioned away from a PKCS#1 v1.5 hard-coded scheme. Some legacy
      code like the use of an encoding block identifier 'bt' will eventually
      be removed. */

    // private key operation
    let bt = false

    if (typeof scheme === 'string') {
      scheme = scheme.toUpperCase()
    }

    if (scheme === undefined || scheme === 'RSASSA-PKCS1-V1_5') {
      scheme = { encode: emsaPkcs1v15encode }
      bt = 0x01
    }
    else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
      scheme = { encode() { return md } }
      bt = 0x01
    }

    // encode and then encrypt
    const d = scheme.encode(md, key.n.bitLength())
    return pki.rsa.encrypt(d, key, bt)
  }

  return key
}

export const setRsaPrivateKey: (n: BigInteger, e: BigInteger, d: BigInteger, p: BigInteger, q: BigInteger, dP: BigInteger, dQ: BigInteger, qInv: BigInteger) => RSAKey = setPrivateKey

/**
 * Wraps an RSAPrivateKey ASN.1 object in an ASN.1 PrivateKeyInfo object.
 *
 * @param rsaKey the ASN.1 RSAPrivateKey.
 *
 * @return the ASN.1 PrivateKeyInfo.
 */
export function wrapRsaPrivateKey(rsaKey: Asn1Object): Asn1Object {
  // PrivateKeyInfo
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version (0)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(0).getBytes()),
    // privateKeyAlgorithm
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.OID,
        false,
        asn1.oidToDer(oids.rsaEncryption).getBytes(),
      ),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
    ]),
    // PrivateKey
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, asn1.toDer(rsaKey).getBytes()),
  ])
}

/**
 * Converts a private key from an ASN.1 object.
 *
 * @param obj the ASN.1 representation of a PrivateKeyInfo containing an RSAPrivateKey or an RSAPrivateKey.
 *
 * @return the private key.
 */
export function privateKeyFromAsn1(obj: Asn1Object): RSAKey {
  // get PrivateKeyInfo
  let capture = {}
  let errors = []
  if (asn1.validate(obj, privateKeyValidator, capture, errors)) {
    obj = asn1.fromDer(createBuffer(capture.privateKey))
  }

  // get RSAPrivateKey
  capture = {}
  errors = []
  if (!asn1.validate(obj, rsaPrivateKeyValidator, capture, errors)) {
    const error = new Error('Cannot read private key. '
      + 'ASN.1 object does not contain an RSAPrivateKey.')
    error.errors = errors
    throw error
  }

  // Note: Version is currently ignored.
  // capture.privateKeyVersion
  // FIXME: inefficient, get a BigInteger that uses byte strings
  let n, e, d, p, q, dP, dQ, qInv
  n = createBuffer(capture.privateKeyModulus).toHex()
  e = createBuffer(capture.privateKeyPublicExponent).toHex()
  d = createBuffer(capture.privateKeyPrivateExponent).toHex()
  p = createBuffer(capture.privateKeyPrime1).toHex()
  q = createBuffer(capture.privateKeyPrime2).toHex()
  dP = createBuffer(capture.privateKeyExponent1).toHex()
  dQ = createBuffer(capture.privateKeyExponent2).toHex()
  qInv = createBuffer(capture.privateKeyCoefficient).toHex()

  // set private key
  return setRsaPrivateKey(
    new BigInteger(n, 16),
    new BigInteger(e, 16),
    new BigInteger(d, 16),
    new BigInteger(p, 16),
    new BigInteger(q, 16),
    new BigInteger(dP, 16),
    new BigInteger(dQ, 16),
    new BigInteger(qInv, 16),
  )
}

/**
 * Converts a private key to an ASN.1 RSAPrivateKey.
 *
 * @param key the private key.
 *
 * @return the ASN.1 representation of an RSAPrivateKey.
 */
export function privateKeyToAsn1(key: {
  n: BigInteger
  e: BigInteger
  d: BigInteger
  p: BigInteger
  q: BigInteger
  dP: BigInteger
  dQ: BigInteger
  qInv: BigInteger
}): Asn1Object {
  // RSAPrivateKey
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version (0 = only 2 primes, 1 multiple primes)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(0).getBytes()),
    // modulus (n)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.n)),
    // publicExponent (e)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.e)),
    // privateExponent (d)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.d)),
    // privateKeyPrime1 (p)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.p)),
    // privateKeyPrime2 (q)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.q)),
    // privateKeyExponent1 (dP)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.dP)),
    // privateKeyExponent2 (dQ)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.dQ)),
    // coefficient (qInv)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.qInv)),
  ])
}

/**
 * Converts a public key from an ASN.1 SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @param obj the asn1 representation of a SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @return the public key.
 */
export function publicKeyFromAsn1(obj: Asn1Object): RSAKey {
  // get SubjectPublicKeyInfo
  const capture = {}
  let errors = []
  if (asn1.validate(obj, publicKeyValidator, capture, errors)) {
    // get oid
    const oid = asn1.derToOid(capture.publicKeyOid)
    if (oid !== oids.rsaEncryption) {
      var error = new Error('Cannot read public key. Unknown OID.')
      error.oid = oid
      throw error
    }
    obj = capture.rsaPublicKey
  }

  // get RSA params
  errors = []
  if (!asn1.validate(obj, rsaPublicKeyValidator, capture, errors)) {
    var error = new Error('Cannot read public key. '
      + 'ASN.1 object does not contain an RSAPublicKey.')
    error.errors = errors
    throw error
  }

  // FIXME: inefficient, get a BigInteger that uses byte strings
  const n = createBuffer(capture.publicKeyModulus).toHex()
  const e = createBuffer(capture.publicKeyExponent).toHex()

  // set public key
  return setRsaPublicKey(
    new BigInteger(n, 16),
    new BigInteger(e, 16),
  )
}

/**
 * Converts a public key to an ASN.1 SubjectPublicKeyInfo.
 *
 * @param key the public key.
 *
 * @return the asn1 representation of a SubjectPublicKeyInfo.
 */
export function publicKeyToAsn1(key: RSAKey): Asn1Object {
  // SubjectPublicKeyInfo
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // AlgorithmIdentifier
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids.rsaEncryption).getBytes()),
      // parameters (null)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
    ]),
    // subjectPublicKey
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, [
      pki.publicKeyToRSAPublicKey(key),
    ]),
  ])
}

export const publicKeyToSubjectPublicKeyInfo: (key: RSAKey) => Asn1Object = publicKeyToAsn1

/**
 * Converts a public key to an ASN.1 RSAPublicKey.
 *
 * @param key the public key.
 *
 * @return the asn1 representation of a RSAPublicKey.
 */
export function publicKeyToRSAPublicKey(key: {
  n: BigInteger
  e: BigInteger
}): Asn1Object {
  // RSAPublicKey
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // modulus (n)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.n)),
    // publicExponent (e)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, _bnToBytes(key.e)),
  ])
}

/**
 * Encodes a message using PKCS#1 v1.5 padding.
 *
 * @param m the message to encode.
 * @param key the RSA key to use.
 * @param bt the block type to use, i.e. either 0x01 (for signing) or 0x02
 *          (for encryption).
 *
 * @return the padded byte buffer.
 */
function _encodePkcs1_v1_5(m: string, key: {
  n: BigInteger
  e: BigInteger
}, bt: number) {
  const eb = createBuffer()

  // get the length of the modulus in bytes
  const k = Math.ceil(key.n.bitLength() / 8)

  /* use PKCS#1 v1.5 padding */
  if (m.length > (k - 11)) {
    const error = new Error('Message is too long for PKCS#1 v1.5 padding.')
    error.length = m.length
    error.max = k - 11
    throw error
  }

  /* A block type BT, a padding string PS, and the data D shall be
    formatted into an octet string EB, the encryption block:

    EB = 00 || BT || PS || 00 || D

    The block type BT shall be a single octet indicating the structure of
    the encryption block. For this version of the document it shall have
    value 00, 01, or 02. For a private-key operation, the block type
    shall be 00 or 01. For a public-key operation, it shall be 02.

    The padding string PS shall consist of k-3-||D|| octets. For block
    type 00, the octets shall have value 00; for block type 01, they
    shall have value FF; and for block type 02, they shall be
    pseudorandomly generated and nonzero. This makes the length of the
    encryption block EB equal to k. */

  // build the encryption block
  eb.putByte(0x00)
  eb.putByte(bt)

  // create the padding
  let padNum = k - 3 - m.length
  let padByte
  // private key op
  if (bt === 0x00 || bt === 0x01) {
    padByte = (bt === 0x00) ? 0x00 : 0xFF
    for (var i = 0; i < padNum; ++i) {
      eb.putByte(padByte)
    }
  }
  else {
    // public key op
    // pad with random non-zero values
    while (padNum > 0) {
      let numZeros = 0
      const padBytes = random.getBytes(padNum)
      for (var i = 0; i < padNum; ++i) {
        padByte = padBytes.charCodeAt(i)
        if (padByte === 0) {
          ++numZeros
        }
        else {
          eb.putByte(padByte)
        }
      }
      padNum = numZeros
    }
  }

  // zero followed by message
  eb.putByte(0x00)
  eb.putBytes(m)

  return eb
}

/**
 * Decodes a message using PKCS#1 v1.5 padding.
 *
 * @param em the message to decode.
 * @param key the RSA key to use.
 * @param pub true if the key is a public key, false if it is private.
 * @param ml the message length, if specified.
 *
 * @return the decoded bytes.
 */
function _decodePkcs1_v1_5(em: string, key: {
  n: BigInteger
  e: BigInteger
}, pub: boolean, ml?: number) {
  // get the length of the modulus in bytes
  const k = Math.ceil(key.n.bitLength() / 8)

  /* It is an error if any of the following conditions occurs:

    1. The encryption block EB cannot be parsed unambiguously.
    2. The padding string PS consists of fewer than eight octets
      or is inconsisent with the block type BT.
    3. The decryption process is a public-key operation and the block
      type BT is not 00 or 01, or the decryption process is a
      private-key operation and the block type is not 02.
   */

  // parse the encryption block
  const eb = createBuffer(em)
  const first = eb.getByte()
  const bt = eb.getByte()
  if (first !== 0x00
    || (pub && bt !== 0x00 && bt !== 0x01)
    || (!pub && bt != 0x02)
    || (pub && bt === 0x00 && typeof (ml) === 'undefined')) {
    throw new Error('Encryption block is invalid.')
  }

  let padNum = 0
  if (bt === 0x00) {
    // check all padding bytes for 0x00
    padNum = k - 3 - ml
    for (let i = 0; i < padNum; ++i) {
      if (eb.getByte() !== 0x00) {
        throw new Error('Encryption block is invalid.')
      }
    }
  }
  else if (bt === 0x01) {
    // find the first byte that isn't 0xFF, should be after all padding
    padNum = 0
    while (eb.length() > 1) {
      if (eb.getByte() !== 0xFF) {
        --eb.read
        break
      }
      ++padNum
    }
  }
  else if (bt === 0x02) {
    // look for 0x00 byte
    padNum = 0
    while (eb.length() > 1) {
      if (eb.getByte() === 0x00) {
        --eb.read
        break
      }
      ++padNum
    }
  }

  // zero must be 0x00 and padNum must be (k - 3 - message length)
  const zero = eb.getByte()
  if (zero !== 0x00 || padNum !== (k - 3 - eb.length())) {
    throw new Error('Encryption block is invalid.')
  }

  return eb.getBytes()
}

/**
 * Runs the key-generation algorithm asynchronously, either in the background
 * via Web Workers, or using the main thread and setImmediate.
 *
 * @param state the key-pair generation state.
 * @param [options] options for key-pair generation:
 *          workerScript the worker script URL.
 *          workers the number of web workers (if supported) to use,
 *            (default: 2, -1 to use estimated cores minus one).
 *          workLoad the size of the work load, ie: number of possible prime
 *            numbers for each web worker to check per work assignment,
 *            (default: 100).
 * @param callback(err, keypair) called once the operation completes.
 */
function _generateKeyPair(state: {
  pBits: number
  qBits: number
  bits: number
  e: BigInteger
}, options: {
  algorithm?: string
  workers?: number
  workLoad?: number
  workerScript?: string
}, callback: (err: any, keypair: any) => void) {
  if (typeof options === 'function') {
    callback = options
    options = {}
  }
  options = options || {}

  const opts = {
    algorithm: {
      name: options.algorithm || 'PRIMEINC',
      options: {
        workers: options.workers || 2,
        workLoad: options.workLoad || 100,
        workerScript: options.workerScript,
      },
    },
  }
  if ('prng' in options) {
    opts.prng = options.prng
  }

  generate()

  function generate() {
    // find p and then q (done in series to simplify)
    getPrime(state.pBits, (err: any, num: any) => {
      if (err) {
        return callback(err)
      }

      state.p = num
      if (state.q !== null) {
        return finish(err, state.q)
      }

      getPrime(state.qBits, finish)
    })
  }

  function getPrime(bits: number, callback: (err: any, num: any) => void) {
    forge.prime.generateProbablePrime(bits, opts, callback)
  }

  function finish(err: any, num: any) {
    if (err) {
      return callback(err)
    }

    // set q
    state.q = num

    // ensure p is larger than q (swap them if not)
    if (state.p.compareTo(state.q) < 0) {
      const tmp = state.p
      state.p = state.q
      state.q = tmp
    }

    // ensure p is coprime with e
    if (state.p.subtract(BigInteger.ONE).gcd(state.e).compareTo(BigInteger.ONE) !== 0) {
      state.p = null
      generate()
      return
    }

    // ensure q is coprime with e
    if (state.q.subtract(BigInteger.ONE).gcd(state.e).compareTo(BigInteger.ONE) !== 0) {
      state.q = null
      getPrime(state.qBits, finish)
      return
    }

    // compute phi: (p - 1)(q - 1) (Euler's totient function)
    state.p1 = state.p.subtract(BigInteger.ONE)
    state.q1 = state.q.subtract(BigInteger.ONE)
    state.phi = state.p1.multiply(state.q1)

    // ensure e and phi are coprime
    if (state.phi.gcd(state.e).compareTo(BigInteger.ONE) !== 0) {
      // phi and e aren't coprime, so generate a new p and q
      state.p = state.q = null
      generate()
      return
    }

    // create n, ensure n is has the right number of bits
    state.n = state.p.multiply(state.q)
    if (state.n.bitLength() !== state.bits) {
      // failed, get new q
      state.q = null
      getPrime(state.qBits, finish)
      return
    }

    // set keys
    const d = state.e.modInverse(state.phi)
    state.keys = {
      privateKey: pki.rsa.setPrivateKey(
        state.n,
        state.e,
        d,
        state.p,
        state.q,
        d.mod(state.p1),
        d.mod(state.q1),
        state.q.modInverse(state.p),
      ),
      publicKey: setRsaPublicKey(state.n, state.e),
    }

    callback(null, state.keys)
  }
}

/**
 * Converts a positive BigInteger into 2's-complement big-endian bytes.
 *
 * @param b the big integer to convert.
 *
 * @return the bytes.
 */
function _bnToBytes(b: BigInteger) {
  // prepend 0x00 if first byte >= 0x80
  let hex = b.toString(16)
  if (hex[0] >= '8') {
    hex = `00${hex}`
  }

  const bytes = hexToBytes(hex)

  // ensure integer is minimally-encoded
  if (bytes.length > 1
    // leading 0x00 for positive integer
    && ((bytes.charCodeAt(0) === 0
      && (bytes.charCodeAt(1) & 0x80) === 0)
    // leading 0xFF for negative integer
    || (bytes.charCodeAt(0) === 0xFF
      && (bytes.charCodeAt(1) & 0x80) === 0x80))) {
    return bytes.substr(1)
  }

  return bytes
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
function _getMillerRabinTests(bits: number) {
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

/**
 * Performs feature detection on the Node crypto interface.
 *
 * @param fn the feature (function) to detect.
 *
 * @return true if detected, false if not.
 */
export function detectNodeCrypto(fn: string): boolean {
  return isServer && typeof _crypto[fn] === 'function'
}

/**
 * Performs feature detection on the SubtleCrypto interface.
 *
 * @param fn the feature (function) to detect.
 *
 * @return true if detected, false if not.
 */
export function detectSubtleCrypto(fn: string): boolean {
  return (typeof util.globalScope !== 'undefined'
    && typeof util.globalScope.crypto === 'object'
    && typeof util.globalScope.crypto.subtle === 'object'
    && typeof util.globalScope.crypto.subtle[fn] === 'function')
}

/**
 * Performs feature detection on the deprecated Microsoft Internet Explorer
 * outdated SubtleCrypto interface. This function should only be used after
 * checking for the modern, standard SubtleCrypto interface.
 *
 * @param fn the feature (function) to detect.
 *
 * @return true if detected, false if not.
 */
export function detectSubtleMsCrypto(fn: string): boolean {
  return (typeof util.globalScope !== 'undefined'
    && typeof util.globalScope.msCrypto === 'object'
    && typeof util.globalScope.msCrypto.subtle === 'object'
    && typeof util.globalScope.msCrypto.subtle[fn] === 'function')
}

export function intToUint8Array(x: number): Uint8Array {
  const bytes = hexToBytes(x.toString(16))
  const buffer = new Uint8Array(bytes.length)

  for (let i = 0; i < bytes.length; ++i) {
    buffer[i] = bytes.charCodeAt(i)
  }

  return buffer
}

export function privateKeyFromJwk(jwk: {
  kty: string
  n: string
  e: string
  d: string
  p: string
  q: string
  dp: string
  dq: string
  qi: string
}): RSAKey {
  if (jwk.kty !== 'RSA') {
    throw new Error(
      `Unsupported key algorithm "${jwk.kty}"; algorithm must be "RSA".`,
    )
  }
  return setRsaPrivateKey(
    _base64ToBigInt(jwk.n),
    _base64ToBigInt(jwk.e),
    _base64ToBigInt(jwk.d),
    _base64ToBigInt(jwk.p),
    _base64ToBigInt(jwk.q),
    _base64ToBigInt(jwk.dp),
    _base64ToBigInt(jwk.dq),
    _base64ToBigInt(jwk.qi),
  )
}

export function publicKeyFromJwk(jwk: {
  kty: string
  n: string
  e: string
}): RSAKey {
  if (jwk.kty !== 'RSA') {
    throw new Error('Key algorithm must be "RSA".')
  }
  return setRsaPublicKey(
    _base64ToBigInt(jwk.n),
    _base64ToBigInt(jwk.e),
  )
}

export function base64ToBigInt(b64: string): BigInteger {
  return new BigInteger(bytesToHex(decode64(b64)), 16)
}

export function addRSAKeyOps(key: RSAKey): RSAKeyWithOps {
  const keyWithOps = key as RSAKeyWithOps
  keyWithOps.encrypt = function(data: string | Uint8Array, scheme: string, schemeOptions?: any) {
    let encodeScheme: EncodeScheme
    if (scheme === 'RSAES-PKCS1-V1_5') {
      encodeScheme = {
        encode(m: string | Uint8Array, key: RSAKey, pub: boolean) {
          return _encodePkcs1_v1_5(m as string, key, 0x02).getBytes()
        }
      }
    } else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      encodeScheme = {
        encode(m: string, key: RSAKey) {
          return encode_rsa_oaep(key, m, schemeOptions)
        },
      }
    } else if (['RAW', 'NONE', 'NULL', null].includes(scheme)) {
      encodeScheme = { encode(e) { return e } }
    } else if (typeof scheme === 'string') {
      throw new TypeError(`Unsupported encryption scheme: "${scheme}".`)
    }

    // do scheme-based encoding then rsa encryption
    const e = encodeScheme.encode(data, key, true)

    return encrypt(e, key, true)
  }

  keyWithOps.decrypt = function(data: string | Uint8Array, scheme: string, schemeOptions?: any) {
    let decodeScheme
    if (scheme === 'RSAES-PKCS1-V1_5') {
      decodeScheme = { decode: _decodePkcs1_v1_5 }
    } else if (scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      decodeScheme = {
        decode(d: string, key: any) {
          return pkcs1.decode_rsa_oaep(key, d, schemeOptions)
        },
      }
    } else if (['RAW', 'NONE', 'NULL', null].includes(scheme)) {
      decodeScheme = { decode(d) { return d } }
    } else if (typeof scheme === 'string') {
      throw new TypeError(`Unsupported encryption scheme: "${scheme}".`)
    }

    // do scheme-based decoding then rsa decryption
    const d = decodeScheme?.decode(data, key, false)

    return decrypt(d, key, false, false)
  }

  keyWithOps.sign = function(md: string | Uint8Array, scheme?: string) {
    let signScheme
    if (scheme === 'RSASSA-PKCS1-V1_5' || scheme === undefined) {
      signScheme = { encode: emsaPkcs1v15encode }
    } else if (scheme === 'RSASSA-PSS') {
      signScheme = { encode: emsaPssEncode }
    } else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
      signScheme = { encode() { return md } }
    } else {
      throw new TypeError(`Unsupported signature scheme: "${scheme}".`)
    }

    // do scheme-based signing then rsa encryption
    const d = signScheme.encode(md, key.n.bitLength())
    return encrypt(d, key, true)
  }

  keyWithOps.verify = function(digest: string | Uint8Array, signature: string | Uint8Array, scheme: string, options: any) {
    if (typeof scheme === 'string') {
      scheme = scheme.toUpperCase()
    }
    else if (scheme === undefined) {
      scheme = 'RSASSA-PKCS1-V1_5'
    }
    if (options === undefined) {
      options = {
        _parseAllDigestBytes: true,
      }
    }
    if (!('_parseAllDigestBytes' in options)) {
      options._parseAllDigestBytes = true
    }

    if (scheme === 'RSASSA-PKCS1-V1_5') {
      scheme = {
        verify(digest, d) {
          // remove padding
          d = _decodePkcs1_v1_5(d, key, true)
          // d is ASN.1 BER-encoded DigestInfo
          const obj = asn1.fromDer(d, {
            parseAllBytes: options._parseAllDigestBytes,
          })

          // validate DigestInfo
          const capture = {}
          const errors = []
          if (!asn1.validate(obj, digestInfoValidator, capture, errors)) {
            var error = new Error(
              'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 '
              + 'DigestInfo value.',
            )
            error.errors = errors
            throw error
          }
          // check hash algorithm identifier
          // see PKCS1-v1-5DigestAlgorithms in RFC 8017
          // FIXME: add support to vaidator for strict value choices
          const oid = asn1.derToOid(capture.algorithmIdentifier)
          if (!(oid === oids.md2
            || oid === oids.md5
            || oid === oids.sha1
            || oid === oids.sha224
            || oid === oids.sha256
            || oid === oids.sha384
            || oid === oids.sha512
            || oid === oids['sha512-224']
            || oid === oids['sha512-256'])) {
            var error = new Error(
              'Unknown RSASSA-PKCS1-v1_5 DigestAlgorithm identifier.',
            )
            error.oid = oid
            throw error
          }

          // special check for md2 and md5 that NULL parameters exist
          if (oid === oids.md2 || oid === oids.md5) {
            if (!('parameters' in capture)) {
              throw new Error(
                'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 '
                + 'DigestInfo value. '
                + 'Missing algorithm identifier NULL parameters.',
              )
            }
          }

          // compare the given digest to the decrypted one
          return digest === capture.digest
        },
      }
    }
    else if (scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
      scheme = {
        verify(digest, d) {
          // remove padding
          d = _decodePkcs1_v1_5(d, key, true)
          return digest === d
        },
      }
    }

    // do rsa decryption w/o any decoding, then verify -- which does decoding
    const d = decrypt(signature, key, true, false)

    return scheme.verify(digest, d, key.n.bitLength())
  }

  return keyWithOps
}
