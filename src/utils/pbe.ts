/**
 * Password-based encryption functions.
 *
 * @author Dave Longley
 * @author Stefan Siegl <stesie@brokenpipe.de>
 * @author Chris Breuer
 *
 * An EncryptedPrivateKeyInfo:
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *   encryptedData        EncryptedData }
 *
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * EncryptedData ::= OCTET STRING
 */

import type { ByteStringBuffer } from '.'
import type { MessageDigest } from '../algorithms/hash/sha1'
import type { BlockCipher } from '../algorithms/symmetric/cipher'
import type { Asn1Object } from '../encoding/asn1'
import type { PemHeader, PemMessage } from '../encoding/pem'
import { Buffer } from 'node:buffer'
import { bytesToHex, ByteStringBuffer as ByteStringBuff, createBuffer, hexToBytes } from '.'
import { privateKeyFromAsn1, privateKeyToAsn1, wrapRsaPrivateKey } from '../algorithms/asymmetric/rsa'
import { sha1 } from '../algorithms/hash/sha1'
import { sha512 } from '../algorithms/hash/sha512'
import { aes } from '../algorithms/symmetric/aes'
import { createCipher, createCipher as createCipherOriginal } from '../algorithms/symmetric/cipher'
import { des } from '../algorithms/symmetric/des'
import { rc2 } from '../algorithms/symmetric/rc2'
import { asn1 } from '../encoding/asn1'
import { pem } from '../encoding/pem'
import { oids } from '../oids'
import { pbkdf2 } from '../utils/pbkdf2'
import { getBytesSync } from '../utils/random'

// Error codes enum
export const PBEErrorCode = {
  INVALID_PARAMS: 'INVALID_PARAMS',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
} as const

// Custom error class
export class PBEError extends Error {
  public readonly details: Record<string, unknown> | undefined

  constructor(
    message: string,
    public readonly code: keyof typeof PBEErrorCode,
    details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'PBEError'
    this.details = details
  }
}

interface CustomError extends Error {
  algorithm?: string
  oid?: string
  errors?: Error[]
  headerType?: string
  supportedOids?: string[]
  supported?: string[]
}

interface EncryptionOptions {
  algorithm?: string
  legacy?: boolean
  prfAlgorithm?: string
  saltSize?: number
  count?: number
}

interface CipherInput {
  iv?: ByteStringBuffer | string
  key?: ByteStringBuffer | string
}

interface HashFunction {
  create: () => MessageDigest
}

interface HashAlgorithms {
  [key: string]: HashFunction
}

interface CipherCreator {
  (key: string | ByteStringBuffer): BlockCipher
}

interface CipherFunction {
  (key: string | ByteStringBuffer, bits: string): BlockCipher
}

interface DESCipherFunction {
  (key: string | ByteStringBuffer, iv: ByteStringBuffer): BlockCipher
}

interface CaptureObject {
  encryptionOid?: string
  encryptionParams?: any
  encryptedData?: string
  kdfOid?: string
  kdfSalt?: string
  kdfIterationCount?: string
  prfOid?: string
  encOid?: string
  encIv?: string
  salt?: string
  iterations?: string
  keyLength?: string
}

interface CipherOptions {
  iv: ByteStringBuffer
  key?: ByteStringBuffer
  output?: ByteStringBuffer
  decrypt?: boolean
}

interface PBECipherInfo {
  cipher: string
  keyLength: number
  ivLength: number
}

interface PBEAlgorithmsMap {
  [key: string]: PBECipherInfo
}

interface SHA512APIMap {
  [key: string]: MessageDigest
}

// Constants
const DEFAULT_ENCRYPTION_PARAMS = {
  prfAlgorithm: 'hmacWithSHA1',
} as const

// PBE algorithms configuration
const pbeAlgorithms: PBEAlgorithmsMap = {
  'aes128-CBC': { cipher: 'AES-CBC', keyLength: 16, ivLength: 16 },
  'aes192-CBC': { cipher: 'AES-CBC', keyLength: 24, ivLength: 16 },
  'aes256-CBC': { cipher: 'AES-CBC', keyLength: 32, ivLength: 16 },
  'des-EDE3-CBC': { cipher: '3DES-CBC', keyLength: 24, ivLength: 8 },
  'desCBC': { cipher: 'DES-CBC', keyLength: 8, ivLength: 8 },
}

// Constants for supported algorithms
const SUPPORTED_KDF_OIDS = [
  oids.pkcs5PBKDF2,
] as const

const SUPPORTED_ENC_OIDS = Object.keys(pbeAlgorithms).map(key => oids[key as keyof typeof oids]) as string[]

// Type definitions
interface EncryptionParams {
  kdfOid: string
  encOid: string
  salt: ByteStringBuffer
  iterationCount: number
  iv: ByteStringBuffer
  encryptedData: ByteStringBuffer
  algorithm?: string // Optional for backward compatibility
}

interface StringKeyValuePairs {
  [key: string]: string | undefined
}

// Custom error types for OID validation
class UnsupportedAlgorithmError extends Error {
  constructor(
    public readonly oid: string,
    public readonly supportedOids: string[],
    message: string,
  ) {
    super(message)
    this.name = 'UnsupportedAlgorithmError'
  }
}

// Type for ASN.1 validation capture
interface ASN1ValidationCapture {
  kdfOid?: string
  encOid?: string
  salt?: string
  iterationCount?: string
  iv?: string
  encryptedData?: string
}

// Helper function to safely extract string values
function extractString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

// Helper function to convert ASN.1 object to validation capture
function toValidationCapture(obj: unknown): ASN1ValidationCapture {
  if (typeof obj !== 'object' || obj === null) {
    return {}
  }

  const asObject = obj as Record<string, unknown>

  return {
    kdfOid: extractString(asObject.kdfOid),
    encOid: extractString(asObject.encOid),
    salt: extractString(asObject.salt),
    iterationCount: extractString(asObject.iterationCount),
    iv: extractString(asObject.iv),
    encryptedData: extractString(asObject.encryptedData),
  }
}

// Update extractEncryptionParams function
function extractEncryptionParams(obj: unknown): EncryptionParams {
  const capture = toValidationCapture(obj)

  // Validate KDF OID
  if (!capture.kdfOid) {
    throw new Error('Missing required KDF OID')
  }

  const kdfOid = capture.kdfOid
  if (!SUPPORTED_KDF_OIDS.includes(kdfOid)) {
    throw new UnsupportedAlgorithmError(
      kdfOid,
      Array.from(SUPPORTED_KDF_OIDS),
      `Unsupported KDF algorithm: ${kdfOid}`,
    )
  }

  // Validate encryption OID
  if (!capture.encOid) {
    throw new Error('Missing required encryption OID')
  }

  const encOid = capture.encOid
  if (!SUPPORTED_ENC_OIDS.includes(encOid)) {
    throw new UnsupportedAlgorithmError(
      encOid,
      SUPPORTED_ENC_OIDS,
      `Unsupported encryption algorithm: ${encOid}`,
    )
  }

  // Extract and validate required parameters
  const salt = capture.salt ? createBuffer(capture.salt) : undefined
  const iterationCount = capture.iterationCount ? Number.parseInt(capture.iterationCount, 10) : undefined
  const iv = capture.iv ? createBuffer(capture.iv) : undefined
  const encryptedData = capture.encryptedData ? createBuffer(capture.encryptedData) : undefined

  if (!salt || !iterationCount || !iv || !encryptedData) {
    throw new Error('Missing required encryption parameters')
  }

  // Find algorithm name from OID
  const algorithm = Object.keys(pbeAlgorithms).find(key =>
    oids[key as keyof typeof oids] === encOid,
  )

  return {
    kdfOid,
    encOid,
    salt,
    iterationCount,
    iv,
    encryptedData,
    algorithm,
  }
}

// Type for cipher creation functions
interface CipherCreationOptions {
  key: string | ByteStringBuffer
  iv?: ByteStringBuffer
  bits?: string
}

// Helper function to convert ByteStringBuffer to string
function toBufferString(buf: ByteStringBuffer): string {
  return buf.bytes()
}

// Helper function to convert string to Buffer
function toNodeBufferFromString(str: string): Buffer {
  return Buffer.from(str, 'binary')
}

// Helper function to convert ByteStringBuffer to Buffer
function toNodeBufferFromBSB(buf: ByteStringBuffer): Buffer {
  return Buffer.from(buf.bytes(), 'binary')
}

// Helper function to convert any input to ByteStringBuffer
function toByteStringBuffer(input: string | Buffer | ByteStringBuffer): ByteStringBuffer {
  if (input instanceof ByteStringBuff)
    return input

  if (typeof input === 'string')
    return createBuffer(input)

  return createBuffer(input.toString('binary'))
}

// Helper function to convert any input to string
function convertToString(input: ByteStringBuffer | string): string {
  if (typeof input === 'string')
    return input

  return input.bytes()
}

// Update cipher creation functions
function createAESCipher(key: string | ByteStringBuffer, bits: string = '128'): BlockCipher {
  const keyStr = convertToString(key)

  return aes.createEncryptionCipher(keyStr, bits)
}

function createDESCipher(key: string | ByteStringBuffer, iv: ByteStringBuffer): BlockCipher {
  const keyStr = convertToString(key)
  const ivBuffer = toNodeBufferFromBSB(iv)

  return des.createEncryptionCipher(keyStr, ivBuffer)
}

function createModernCipher(algorithm: string, key: ByteStringBuffer | string): BlockCipher {
  const keyStr = convertToString(key)
  const iv = createBuffer(getBytesSync(8))

  switch (algorithm) {
    case 'AES-CBC':
      return createAESCipher(keyStr, '128')
    case '3DES-CBC':
      return createDESCipher(keyStr, iv)
    case 'DES-CBC':
      return createDESCipher(keyStr, iv)
    default:
      throw new PBEError(
        `Unsupported cipher algorithm: ${algorithm}`,
        PBEErrorCode.UNSUPPORTED_ALGORITHM,
      )
  }
}

function createLegacyDecipher(algorithm: string, key: string): BlockCipher {
  const iv = createBuffer(getBytesSync(8))

  switch (algorithm) {
    case 'DES-CBC':
      return createDESCipher(key, iv)
    case 'DES-EDE3-CBC':
      return createDESCipher(key, iv)
    case 'AES-128-CBC':
      return createAESCipher(key, '128')
    case 'AES-192-CBC':
      return createAESCipher(key, '192')
    case 'AES-256-CBC':
      return createAESCipher(key, '256')
    case 'RC2-40-CBC':
      return rc2.createDecryptionCipher(key, 40)
    case 'RC2-64-CBC':
      return rc2.createDecryptionCipher(key, 64)
    case 'RC2-128-CBC':
      return rc2.createDecryptionCipher(key, 128)
    default:
      throw new PBEError(
        `Unsupported encryption algorithm: ${algorithm}`,
        PBEErrorCode.UNSUPPORTED_ALGORITHM,
      )
  }
}

// Update PBKDF2 related functions
function deriveKeyPBKDF2(
  password: string,
  options: {
    salt: ByteStringBuffer
    iterationCount: number
    prf: string
  },
): ByteStringBuffer {
  const { salt, iterationCount, prf } = options
  const md = prfAlgorithmToMessageDigest(prf)
  const saltBuffer = toNodeBufferFromBSB(salt)
  const result = pbkdf2(toNodeBufferFromString(password), saltBuffer, iterationCount, 32, md, undefined)
  return result ? createBuffer(result) : createBuffer('')
}

// Update generatePkcs12Key function
export function generatePkcs12Key(
  password: string,
  salt: ByteStringBuffer,
  id: number,
  iter: number,
  n: number,
  md?: MessageDigest,
): ByteStringBuffer {
  if (!md) {
    md = sha1.create()
  }

  const u = md.digestLength
  const v = md.blockLength
  const result = new ByteStringBuff()

  const passBuf = new ByteStringBuff()
  if (password) {
    for (let l = 0; l < password.length; l++)
      passBuf.putInt16(password.charCodeAt(l))

    passBuf.putInt16(0)
  }

  const p = passBuf.length()
  const s = salt.length()

  const D = new ByteStringBuff()
  D.fillWithByte(id, v)

  const Slen = v * Math.ceil(s / v)
  const S = new ByteStringBuff()

  for (let l = 0; l < Slen; l++)
    S.putByte(salt.at(l % s))

  const Plen = v * Math.ceil(p / v)
  const P = new ByteStringBuff()

  for (let l = 0; l < Plen; l++)
    P.putByte(passBuf.at(l % p))

  let I = S
  I.putBuffer(P)

  const c = Math.ceil(n / u)

  for (let i = 1; i <= c; i++) {
    let buf = new ByteStringBuff()
    buf.putBytes(D.bytes())
    buf.putBytes(I.bytes())

    for (let round = 0; round < iter; round++) {
      md.start()
      md.update(buf.getBytes())
      buf = md.digest()
    }

    const B = new ByteStringBuff()
    for (let l = 0; l < v; l++)
      B.putByte(buf.at(l % u))

    const k = Math.ceil(s / v) + Math.ceil(p / v)
    const Inew = new ByteStringBuff()
    for (let j = 0; j < k; j++) {
      const chunk = new ByteStringBuff(I.getBytes(v))
      let x = 0x1FF

      for (let l = B.length() - 1; l >= 0; l--) {
        x = x >> 8
        x += B.at(l) + chunk.at(l)
        chunk.setAt(l, x & 0xFF)
      }

      Inew.putBuffer(chunk)
    }

    I = Inew
    result.putBuffer(buf)
  }

  result.truncate(result.length() - n)
  return result
}

// Update the validator to properly type the capture object
const encryptedPrivateKeyValidator = {
  name: 'EncryptedPrivateKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'EncryptedPrivateKeyInfo.encryptionAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'kdfOid',
    }, {
      name: 'AlgorithmIdentifier.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        name: 'PBKDF2-params.salt',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OCTETSTRING,
        constructed: false,
        capture: 'kdfSalt',
      }, {
        name: 'PBKDF2-params.iterationCount',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'kdfIterationCount',
      }],
    }],
  }, {
    name: 'EncryptedPrivateKeyInfo.encryptionScheme',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'encOid',
    }, {
      name: 'AlgorithmIdentifier.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      constructed: false,
      capture: 'encIv',
    }],
  }, {
    name: 'EncryptedPrivateKeyInfo.encryptedData',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'encryptedData',
  }],
} as const

// validator for a PBES2Algorithms structure
// Note: Currently only works w/PBKDF2 + AES encryption schemes
const PBES2AlgorithmsValidator = {
  name: 'PBES2Algorithms',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'PBES2Algorithms.keyDerivationFunc',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'PBES2Algorithms.keyDerivationFunc.oid',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'kdfOid',
    }, {
      name: 'PBES2Algorithms.params',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        name: 'PBES2Algorithms.params.salt',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OCTETSTRING,
        constructed: false,
        capture: 'kdfSalt',
      }, {
        name: 'PBES2Algorithms.params.iterationCount',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'kdfIterationCount',
      }, {
        name: 'PBES2Algorithms.params.keyLength',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        optional: true,
        capture: 'keyLength',
      }, {
        // prf
        name: 'PBES2Algorithms.params.prf',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        optional: true,
        value: [{
          name: 'PBES2Algorithms.params.prf.algorithm',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.OID,
          constructed: false,
          capture: 'prfOid',
        }],
      }],
    }],
  }, {
    name: 'PBES2Algorithms.encryptionScheme',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'PBES2Algorithms.encryptionScheme.oid',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'encOid',
    }, {
      name: 'PBES2Algorithms.encryptionScheme.iv',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      constructed: false,
      capture: 'encIv',
    }],
  }],
}

const pkcs12PbeParamsValidator = {
  name: 'pkcs-12PbeParams',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'pkcs-12PbeParams.salt',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'salt',
  }, {
    name: 'pkcs-12PbeParams.iterations',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'iterations',
  }],
}

function toNodeBuffer(input: string | ByteStringBuffer): Buffer {
  if (typeof input === 'string') {
    return Buffer.from(input)
  }
  return Buffer.from(input.bytes(), 'binary')
}

/**
 * Encrypts a ASN.1 PrivateKeyInfo object, producing an EncryptedPrivateKeyInfo.
 *
 * PBES2Algorithms ALGORITHM-IDENTIFIER ::=
 *   { {PBES2-params IDENTIFIED BY id-PBES2}, ...}
 *
 * id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}
 *
 * PBES2-params ::= SEQUENCE {
 *   keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
 *   encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
 * }
 *
 * PBES2-KDFs ALGORITHM-IDENTIFIER ::=
 *   { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
 *
 * PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
 *
 * PBKDF2-params ::= SEQUENCE {
 *   salt CHOICE {
 *     specified OCTET STRING,
 *     otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
 *   },
 *   iterationCount INTEGER (1..MAX),
 *   keyLength INTEGER (1..MAX) OPTIONAL,
 *   prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
 * }
 *
 * @param obj the ASN.1 PrivateKeyInfo object.
 * @param password the password to encrypt with.
 * @param options:
 *          algorithm the encryption algorithm to use
 *            ('aes128', 'aes192', 'aes256', '3des'), defaults to 'aes128'.
 *          count the iteration count to use.
 *          saltSize the salt size to use.
 *          prfAlgorithm the PRF message digest algorithm to use
 *            ('sha1', 'sha224', 'sha256', 'sha384', 'sha512')
 *
 * @return the ASN.1 EncryptedPrivateKeyInfo.
 */
export function encryptPrivateKeyInfo(obj: any, password: string, options: EncryptionOptions = {}): Asn1Object {
  // set default options
  options = {
    saltSize: 8,
    count: 2048,
    algorithm: 'aes128',
    prfAlgorithm: 'sha1',
    ...options,
  }

  // generate PBE params
  const salt = getBytesSync(options.saltSize!)
  const count = options.count!
  const countBytes = asn1.integerToDer(count)
  let dkLen: number
  let encryptionAlgorithm: Asn1Object
  let encryptedData: string

  if (options.algorithm!.indexOf('aes') === 0 || options.algorithm === 'des') {
    // do PBES2
    let ivLen: number
    let encOid: string
    let cipherFn: CipherCreator

    switch (options.algorithm) {
      case 'aes128':
        dkLen = 16
        ivLen = 16
        encOid = oids['aes128-CBC']
        cipherFn = key => createAESCipher(key)
        break
      case 'aes192':
        dkLen = 24
        ivLen = 16
        encOid = oids['aes192-CBC']
        cipherFn = key => createAESCipher(key)
        break
      case 'aes256':
        dkLen = 32
        ivLen = 16
        encOid = oids['aes256-CBC']
        cipherFn = key => createAESCipher(key)
        break
      case 'des':
        dkLen = 8
        ivLen = 8
        encOid = oids.desCBC
        cipherFn = key => createCipherOriginal('DES-CBC', convertToString(key))
        break
      default:
        const error: CustomError = new Error('Cannot encrypt private key. Unknown encryption algorithm.')
        error.algorithm = options.algorithm
        throw error
    }

    // get PRF message digest
    const prfAlgorithm = `hmacWith${options.prfAlgorithm!.toUpperCase()}`
    const md = prfAlgorithmToMessageDigest(prfAlgorithm)

    // encrypt private key using pbe SHA-1 and AES/DES
    if (!salt)
      throw new Error('Salt is required')
    if (typeof dkLen === 'undefined')
      throw new Error('Key length is required')
    const saltBuffer = toNodeBuffer(salt)
    const dk = pbkdf2(password, saltBuffer, count, dkLen, md, undefined)
    if (!dk)
      throw new Error('Failed to generate derived key')
    if (!cipherFn)
      throw new Error('Cipher function is not defined')
    const iv = createBuffer(getBytesSync(ivLen))
    const cipher = cipherFn(toByteStringBuffer(dk))
    if (!iv)
      throw new Error('IV is required')
    cipher.start({ iv: convertToString(iv) })
    cipher.update(asn1.toDer(obj))
    if (!cipher.finish())
      throw new Error('Failed to finish encryption')

    if (!cipher.output)
      throw new Error('No output from cipher')

    encryptedData = cipher.output.getBytes()

    // get PBKDF2-params
    const params = createPbkdf2Params(Buffer.from(salt).toString('binary'), countBytes, dkLen, prfAlgorithm)

    encryptionAlgorithm = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.SEQUENCE,
      true,
      [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids.pkcs5PBES2).getBytes()),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          // keyDerivationFunc
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids.pkcs5PBKDF2).getBytes()),
            // PBKDF2-params
            params,
          ]),
          // encryptionScheme
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(encOid).getBytes()),
            // iv
            asn1.create(
              asn1.Class.UNIVERSAL,
              asn1.Type.OCTETSTRING,
              false,
              iv,
            ),
          ]),
        ]),
      ],
    )
  }
  else if (options.algorithm === '3des') {
    // Do PKCS12 PBE
    dkLen = 24

    const saltBytes = new ByteStringBuff(salt)
    const dk = generatePkcs12Key(password, createBuffer(saltBytes.bytes()), 1, count, dkLen)
    const iv = generatePkcs12Key(password, createBuffer(saltBytes.bytes()), 2, count, dkLen)
    const cipher = des.createEncryptionCipher(convertToString(dk), convertToString(iv))

    cipher.update(asn1.toDer(obj))
    cipher.finish()
    encryptedData = cipher.output?.getBytes() || ''

    encryptionAlgorithm = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.SEQUENCE,
      true,
      [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids['pbeWithSHAAnd3-KeyTripleDES-CBC']).getBytes()),
        // pkcs-12PbeParams
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // salt
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, saltBytes.bytes()),
          // iteration count
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, countBytes.getBytes()),
        ]),
      ],
    )
  }
  else {
    const error: CustomError = new Error('Cannot encrypt private key. Unknown encryption algorithm.')
    error.algorithm = options.algorithm
    throw error
  }

  // EncryptedPrivateKeyInfo
  const rval = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // encryptionAlgorithm
    encryptionAlgorithm,
    // encryptedData
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.OCTETSTRING,
      false,
      encryptedData,
    ),
  ])
  return rval
}

/**
 * Decrypts a ASN.1 PrivateKeyInfo object.
 *
 * @param obj the ASN.1 EncryptedPrivateKeyInfo object.
 * @param password the password to decrypt with.
 *
 * @return the ASN.1 PrivateKeyInfo on success, null on failure.
 */
export function decryptPrivateKeyInfo(obj: any, password: string): any {
  let rval = null

  // get PBE params
  const capture: CaptureObject = {}
  const errors: Error[] = []

  if (!asn1.validate(obj, encryptedPrivateKeyValidator, capture, errors)) {
    const error: CustomError = new Error(
      'Cannot read encrypted private key. ASN.1 object is not a supported EncryptedPrivateKeyInfo.',
    )
    error.errors = errors
    throw error
  }

  // get cipher
  const oid = asn1.derToOid(capture.encryptionOid!)
  const cipher = getCipher(oid, capture.encryptionParams!, password)

  // get encrypted data
  const encrypted = createBuffer(capture.encryptedData!)

  cipher.update(encrypted)
  if (cipher.finish() && cipher.output) {
    rval = asn1.fromDer(cipher.output.getBytes() || '')
  }

  return rval
}

/**
 * Converts a EncryptedPrivateKeyInfo to PEM format.
 *
 * @param epki the EncryptedPrivateKeyInfo.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted encrypted private key.
 */
export function encryptedPrivateKeyToPem(epki: Asn1Object, maxline: number): string {
  const msg: PemMessage = {
    type: 'ENCRYPTED PRIVATE KEY',
    body: asn1.toDer(epki).getBytes(),
    procType: null,
    contentDomain: null,
    dekInfo: null,
    headers: [] as PemHeader[],
  }

  return pem.encode(msg, { maxline })
}

/**
 * Converts a PEM-encoded EncryptedPrivateKeyInfo to ASN.1 format. Decryption
 * is not performed.
 *
 * @param pem the EncryptedPrivateKeyInfo in PEM-format.
 *
 * @return the ASN.1 EncryptedPrivateKeyInfo.
 */
export function encryptedPrivateKeyFromPem(pemString: string): any {
  const msg = pem.decode(pemString)[0]

  if (msg.type !== 'ENCRYPTED PRIVATE KEY') {
    const error: CustomError = new Error(
      'Could not convert encrypted private key from PEM; PEM header type is not "ENCRYPTED PRIVATE KEY".',
    )
    error.headerType = msg.type
    throw error
  }

  if (msg.procType?.type === 'ENCRYPTED') {
    throw new Error('Could not convert encrypted private key from PEM; PEM is encrypted.')
  }

  return asn1.fromDer(msg.body)
}

/**
 * Encrypts an RSA private key. By default, the key will be wrapped in
 * a PrivateKeyInfo and encrypted to produce a PKCS#8 EncryptedPrivateKeyInfo.
 * This is the standard, preferred way to encrypt a private key.
 *
 * To produce a non-standard PEM-encrypted private key that uses encapsulated
 * headers to indicate the encryption algorithm (old-style non-PKCS#8 OpenSSL
 * private key encryption), set the 'legacy' option to true. Note: Using this
 * option will cause the iteration count to be forced to 1.
 *
 * Note: The 'des' algorithm is supported, but it is not considered to be
 * secure because it only uses a single 56-bit key. If possible, it is highly
 * recommended that a different algorithm be used.
 *
 * @param rsaKey the RSA key to encrypt.
 * @param password the password to use.
 * @param options options for the encryption
 * @param options.algorithm the encryption algorithm to use ('aes128', 'aes192', 'aes256', '3des', 'des').
 * @param options.count the iteration count to use.
 * @param options.saltSize the salt size to use.
 * @param options.legacy output an old non-PKCS#8 PEM-encrypted+encapsulated headers (DEK-Info) private key.
 *
 * @return the PEM-encoded ASN.1 EncryptedPrivateKeyInfo.
 */
export function encryptRsaPrivateKey(rsaKey: any, password: string, options: EncryptionOptions = {}): string {
  if (!options.legacy) {
    let rval = wrapRsaPrivateKey(privateKeyToAsn1(rsaKey))
    rval = encryptPrivateKeyInfo(rval, password, options)

    return encryptedPrivateKeyToPem(rval, 64)
  }

  // Legacy implementation...
  let algorithm: string
  let initialIv: ByteStringBuffer
  let dkLen: number
  let cipherFn: CipherCreator

  switch (options.algorithm) {
    case 'aes128':
      algorithm = 'AES-128-CBC'
      dkLen = 16
      initialIv = createBuffer(getBytesSync(16))
      cipherFn = key => aes.createEncryptionCipher(convertToString(key), '128')
      break
    case 'aes192':
      algorithm = 'AES-192-CBC'
      dkLen = 24
      initialIv = createBuffer(getBytesSync(16))
      cipherFn = key => aes.createEncryptionCipher(convertToString(key), '192')
      break
    case 'aes256':
      algorithm = 'AES-256-CBC'
      dkLen = 32
      initialIv = createBuffer(getBytesSync(16))
      cipherFn = key => aes.createEncryptionCipher(convertToString(key), '256')
      break
    case '3des':
      algorithm = 'DES-EDE3-CBC'
      dkLen = 24
      initialIv = createBuffer(getBytesSync(8))
      cipherFn = key => des.createEncryptionCipher(convertToString(key), initialIv.bytes())
      break
    case 'des':
      algorithm = 'DES-CBC'
      dkLen = 8
      initialIv = createBuffer(getBytesSync(8))
      cipherFn = key => des.createEncryptionCipher(convertToString(key), initialIv.bytes())
      break
    default:
      const error: CustomError = new Error(
        `Could not encrypt RSA private key; unsupported encryption algorithm "${options.algorithm}".`,
      )
      error.algorithm = options.algorithm
      throw error
  }

  const dk = opensslDeriveBytes(password, initialIv.bytes(), dkLen, sha1.create())
  const finalIv = createBuffer(getBytesSync(16))
  const cipher = cipherFn(createBuffer(dk))
  if (!finalIv)
    throw new Error('IV is required')
  cipher.start({ iv: convertToString(finalIv) })
  cipher.update(asn1.toDer(privateKeyToAsn1(rsaKey)))
  if (!cipher.finish()) {
    throw new Error('Failed to finish encryption')
  }
  if (!cipher.output) {
    throw new Error('No output from cipher')
  }

  const msg: PemMessage = {
    type: 'RSA PRIVATE KEY',
    procType: {
      version: '4',
      type: 'ENCRYPTED',
    },
    dekInfo: {
      algorithm,
      parameters: bytesToHex(finalIv.bytes()).toUpperCase(),
    },
    headers: [],
    body: cipher.output.getBytes(),
    contentDomain: null,
  }

  return pem.encode(msg)
}

/**
 * Decrypts an RSA private key.
 *
 * @param pem the PEM-formatted EncryptedPrivateKeyInfo to decrypt.
 * @param password the password to use.
 *
 * @return the RSA key on success, null on failure.
 */
export function decryptRsaPrivateKey(pemKey: string, password: string): any {
  if (!pemKey || !password) {
    throw new PBEError(
      'PEM key and password are required',
      PBEErrorCode.INVALID_PARAMS,
    )
  }

  let obj: Asn1Object
  try {
    obj = pemToEncryptedPrivateKey(pemKey)
  }
  catch (e) {
    throw new PBEError(
      'Invalid PEM format',
      PBEErrorCode.INVALID_PARAMS,
      { error: e },
    )
  }

  // Try modern PKCS#8 first
  try {
    const params = extractEncryptionParams(obj)
    const key = deriveKeyPBKDF2(password, {
      salt: params.salt,
      iterationCount: params.iterationCount,
      prf: DEFAULT_ENCRYPTION_PARAMS.prfAlgorithm,
    })

    const algorithm = params.algorithm || 'aes128-CBC'
    validateKey(key, pbeAlgorithms[algorithm].keyLength)
    validateIV(params.iv, pbeAlgorithms[algorithm].ivLength)

    const decipher = createModernCipher(
      pbeAlgorithms[algorithm].cipher,
      key,
    )

    decipher.start({ iv: params.iv })
    decipher.update(params.encryptedData)

    if (!decipher.finish()) {
      throw new PBEError(
        'Failed to decrypt private key',
        PBEErrorCode.DECRYPTION_FAILED,
      )
    }

    if (!decipher.output) {
      throw new PBEError(
        'No output from cipher',
        PBEErrorCode.DECRYPTION_FAILED,
      )
    }

    return asn1ToPrivateKey(unwrapRsaPrivateKey(asn1.fromDer(decipher.output.bytes())))
  }
  catch (e) {
    if (e instanceof PBEError && e.code === PBEErrorCode.INVALID_PARAMS) {
      try {
        return decryptRsaPrivateKeyLegacy(pemKey, password)
      }
      catch (legacyError) {
        throw new PBEError(
          'Failed to decrypt private key (both modern and legacy formats)',
          PBEErrorCode.DECRYPTION_FAILED,
          {
            modernError: e,
            legacyError,
          },
        )
      }
    }
    throw e
  }
}

/**
 * Get new cipher object instance.
 *
 * @param oid the OID (in string notation).
 * @param params the ASN.1 params object.
 * @param password the password to decrypt with.
 *
 * @return new cipher object instance.
 */
export function getCipher(oid: string, params: any, password: string): BlockCipher {
  switch (oid) {
    case oids.pkcs5PBES2:
      return getCipherForPBES2(oid, params, password)

    case oids['pbeWithSHAAnd3-KeyTripleDES-CBC']:
    case oids['pbewithSHAAnd40BitRC2-CBC']:
      return getCipherForPKCS12PBE(oid, params, password)

    default:
      const error: CustomError = new Error('Cannot read encrypted PBE data block. Unsupported OID.')
      error.oid = oid
      error.supportedOids = ['pkcs5PBES2', 'pbeWithSHAAnd3-KeyTripleDES-CBC', 'pbewithSHAAnd40BitRC2-CBC']
      throw error
  }
}

/**
 * Get new Forge cipher object instance according to PBES2 params block.
 *
 * The returned cipher instance is already started using the IV
 * from PBES2 parameter block.
 *
 * @param oid the PKCS#5 PBKDF2 OID (in string notation).
 * @param params the ASN.1 PBES2-params object.
 * @param password the password to decrypt with.
 *
 * @return new cipher object instance.
 */
export function getCipherForPBES2(oid: string, params: any, password: string): BlockCipher {
  // get PBE params
  const capture: CaptureObject = {}
  const errors: Error[] = []

  if (!asn1.validate(params, PBES2AlgorithmsValidator, capture, errors)) {
    const error: CustomError = new Error('Cannot read password-based-encryption algorithm parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo.')
    error.errors = errors
    throw error
  }

  // check oids
  oid = asn1.derToOid(capture.kdfOid)
  if (oid !== oids.pkcs5PBKDF2) {
    const error: CustomError = new Error('Cannot read encrypted private key. Unsupported key derivation function OID.')
    error.oid = oid
    error.supportedOids = ['pkcs5PBKDF2']
    throw error
  }
  oid = asn1.derToOid(capture.encOid)
  if (oid !== oids['aes128-CBC']
    && oid !== oids['aes192-CBC']
    && oid !== oids['aes256-CBC']
    && oid !== oids['des-EDE3-CBC']
    && oid !== oids.desCBC) {
    const error: CustomError = new Error('Cannot read encrypted private key. Unsupported encryption scheme OID.')
    error.oid = oid
    error.supportedOids = [
      'aes128-CBC',
      'aes192-CBC',
      'aes256-CBC',
      'des-EDE3-CBC',
      'desCBC',
    ]
    throw error
  }

  // set PBE params
  const salt = capture.kdfSalt
  const countBuffer = createBuffer(capture.kdfIterationCount)
  const iterationCount = countBuffer.getInt(countBuffer.length() << 3)
  let dkLen
  let cipherFn

  switch (oids[oid]) {
    case 'aes128-CBC':
      dkLen = 16
      cipherFn = (key: string) => createCipherOriginal('AES-CBC', key)
      break
    case 'aes192-CBC':
      dkLen = 24
      cipherFn = (key: string) => createCipherOriginal('AES-CBC', key)
      break
    case 'aes256-CBC':
      dkLen = 32
      cipherFn = (key: string) => createCipherOriginal('AES-CBC', key)
      break
    case 'des-EDE3-CBC':
      dkLen = 24
      cipherFn = (key: string) => createCipherOriginal('3DES-CBC', key)
      break
    case 'desCBC':
      dkLen = 8
      cipherFn = (key: string) => createCipherOriginal('DES-CBC', key)
      break
  }

  // get PRF message digest
  const prfAlgorithm = capture.prfOid || 'hmacWithSHA1'
  const md = prfAlgorithmToMessageDigest(prfAlgorithm)

  // decrypt private key using pbe with chosen PRF and AES/DES
  if (!salt)
    throw new Error('Salt is required')
  if (typeof dkLen === 'undefined')
    throw new Error('Key length is required')
  const saltBuffer = toNodeBuffer(salt)
  const dk = pbkdf2(password, saltBuffer, iterationCount, dkLen, md, undefined)
  if (!dk)
    throw new Error('Failed to generate derived key')
  if (!cipherFn)
    throw new Error('Cipher function is not defined')
  const iv = capture.encIv
  const cipher = cipherFn(convertToString(dk))
  if (!iv)
    throw new Error('IV is required')
  cipher.start({ iv: convertToString(iv) })

  return cipher
}

/**
 * Get new Forge cipher object instance for PKCS#12 PBE.
 *
 * The returned cipher instance is already started using the key & IV
 * derived from the provided password and PKCS#12 PBE salt.
 *
 * @param oid The PKCS#12 PBE OID (in string notation).
 * @param params The ASN.1 PKCS#12 PBE-params object.
 * @param password The password to decrypt with.
 *
 * @return the new cipher object instance.
 */
export function getCipherForPKCS12PBE(oid: string, params: Asn1Object, password: string): BlockCipher {
  // get PBE params
  const capture = {}
  const errors: Error[] = []

  if (!asn1.validate(params, pkcs12PbeParamsValidator, capture, errors)) {
    const error: CustomError = new Error('Cannot read password-based-encryption algorithm parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo.')
    error.errors = errors
    throw error
  }

  const validatedCapture = capture as CaptureObject
  const salt = createBuffer(validatedCapture.salt)
  const countBuffer = createBuffer(validatedCapture.iterations)
  const iterationCount = countBuffer.getInt(countBuffer.length() << 3)

  let dkLen, dIvLen, cipherFn
  switch (oid) {
    case oids['pbeWithSHAAnd3-KeyTripleDES-CBC']:
      dkLen = 24
      dIvLen = 8
      cipherFn = function (key: string, iv: string) {
        const cipher = createCipher('3DES-CBC', key)
        cipher.start({ iv })
        return cipher
      }
      break

    case oids['pbewithSHAAnd40BitRC2-CBC']:
      dkLen = 5
      dIvLen = 8
      cipherFn = function (key: string, iv: string) {
        const cipher = rc2.createDecryptionCipher(key, 40)
        cipher.start({ iv })
        return cipher
      }
      break

    default:
      const error: CustomError = new Error('Cannot read PKCS #12 PBE data block. Unsupported OID.')
      error.oid = oid
      throw error
  }

  // get PRF message digest
  const prfAlgorithm = validatedCapture.prfOid || 'hmacWithSHA1'
  const md = prfAlgorithmToMessageDigest(prfAlgorithm)
  const key = generatePkcs12Key(password, salt, 1, iterationCount, dkLen, md)
  md.start()
  const iv = generatePkcs12Key(password, salt, 2, iterationCount, dIvLen, md)

  return cipherFn(convertToString(key), convertToString(iv))
}

/**
 * OpenSSL's legacy key derivation function.
 *
 * See: http://www.openssl.org/docs/crypto/EVP_BytesToKey.html
 *
 * @param password the password to derive the key from.
 * @param salt the salt to use, null for none.
 * @param dkLen the number of bytes needed for the derived key.
 * @param options the options to use:
 * @param options.md an optional message digest object to use.
 */
export function opensslDeriveBytes(password: string, salt: string, dkLen: number, md: any): string {
  if (typeof md === 'undefined' || md === null) {
    if (!('sha1' in md))
      throw new Error('"sha1" hash algorithm unavailable.')

    md = sha1.create()
  }

  if (salt === null)
    salt = ''

  const digests = [hash(md, password + salt)]

  for (let length = 16, i = 1; length < dkLen; ++i, length += 16)
    digests.push(hash(md, digests[i - 1] + password + salt))

  return digests.join('').substr(0, dkLen)
}

export function hash(md: MessageDigest, bytes: string): string {
  return md.start().update(bytes).digest().getBytes()
}

class AlgorithmError extends Error {
  constructor(
    public readonly algorithm: string,
    public readonly supported: string[],
    message: string,
  ) {
    super(message)
    this.name = 'AlgorithmError'
  }
}

export function prfAlgorithmToMessageDigest(prfAlgorithm: string): MessageDigest {
  let factory

  switch (prfAlgorithm) {
    case 'hmacWithSHA224':
      factory = sha512
      break
    case 'hmacWithSHA1':
    case 'hmacWithSHA256':
    case 'hmacWithSHA384':
    case 'hmacWithSHA512':
      prfAlgorithm = prfAlgorithm.substr(8).toLowerCase()
      break
    default:
      throw new AlgorithmError(
        prfAlgorithm,
        ['hmacWithSHA1', 'hmacWithSHA224', 'hmacWithSHA256', 'hmacWithSHA384', 'hmacWithSHA512'],
        'Unsupported PRF algorithm.',
      )
  }

  if (!factory || !(prfAlgorithm in factory))
    throw new Error(`Unknown hash algorithm: ${prfAlgorithm}`)

  return ((factory as unknown) as Record<string, HashFunction>)[prfAlgorithm].create()
}

export function createPbkdf2Params(salt: string, countBytes: ByteStringBuffer, dkLen: number, prfAlgorithm: string): Asn1Object {
  const params = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // salt
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.OCTETSTRING,
      false,
      salt,
    ),

    // iteration count
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, countBytes.getBytes()),
  ])

  // when PRF algorithm is not SHA-1 default, add key length and PRF algorithm
  if (prfAlgorithm !== 'hmacWithSHA1') {
    params.value.push(
      // key length
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, hexToBytes(dkLen.toString(16))),
      // AlgorithmIdentifier
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // algorithm
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids[prfAlgorithm]).getBytes()),
        // parameters (null)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
      ]),
    )
  }

  return params
}

// Custom error types for better type safety
interface PBEErrorDetails {
  algorithm?: string
  supported?: string[]
  errors?: Error[]
}

function validateKey(key: ByteStringBuffer, expectedLength: number): void {
  if (key.length() !== expectedLength) {
    throw new PBEError(
      `Invalid key length: expected ${expectedLength}, got ${key.length()}`,
      PBEErrorCode.INVALID_PARAMS,
    )
  }
}

function validateIV(iv: ByteStringBuffer, expectedLength: number): void {
  if (iv.length() !== expectedLength) {
    throw new PBEError(
      `Invalid IV length: expected ${expectedLength}, got ${iv.length()}`,
      PBEErrorCode.INVALID_PARAMS,
    )
  }
}

function pemToEncryptedPrivateKey(pemKey: string): Asn1Object {
  const msg = pem.decode(pemKey)[0]
  if (msg.type !== 'ENCRYPTED PRIVATE KEY') {
    throw new PBEError(
      'Invalid PEM format: not an encrypted private key',
      PBEErrorCode.INVALID_PARAMS,
    )
  }
  return asn1.fromDer(msg.body)
}

function unwrapRsaPrivateKey(obj: Asn1Object): Asn1Object {
  if (obj.type === asn1.Type.SEQUENCE) {
    return obj
  }
  throw new PBEError(
    'Invalid private key format',
    PBEErrorCode.INVALID_PARAMS,
  )
}

function asn1ToPrivateKey(obj: Asn1Object): any {
  return privateKeyFromAsn1(obj)
}

// Legacy decryption function
function decryptRsaPrivateKeyLegacy(pemKey: string, password: string): any {
  const msg = pem.decode(pemKey)[0]

  if (msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    throw new PBEError(
      'Invalid PEM format: not a legacy private key',
      PBEErrorCode.INVALID_PARAMS,
    )
  }

  if (!msg.procType || msg.procType.type !== 'ENCRYPTED') {
    throw new PBEError(
      'Invalid PEM format: not encrypted',
      PBEErrorCode.INVALID_PARAMS,
    )
  }

  const { algorithm, parameters } = msg.dekInfo || {}
  if (!algorithm || !parameters) {
    throw new PBEError(
      'Invalid PEM format: missing encryption parameters',
      PBEErrorCode.INVALID_PARAMS,
    )
  }

  const iv = hexToBytes(parameters)
  const dk = opensslDeriveBytes(password, iv.substr(0, 8), getDkLen(algorithm), sha1.create())
  const cipher = createLegacyDecipher(algorithm, dk)

  cipher.start({ iv: createBuffer(iv) })
  cipher.update(createBuffer(msg.body))

  if (!cipher.finish()) {
    throw new PBEError(
      'Failed to decrypt private key',
      PBEErrorCode.DECRYPTION_FAILED,
    )
  }

  return privateKeyFromAsn1(asn1.fromDer(cipher.output?.getBytes() || ''))
}

function getDkLen(algorithm: string): number {
  switch (algorithm) {
    case 'DES-CBC': return 8
    case 'DES-EDE3-CBC': return 24
    case 'AES-128-CBC': return 16
    case 'AES-192-CBC': return 24
    case 'AES-256-CBC': return 32
    case 'RC2-40-CBC': return 5
    case 'RC2-64-CBC': return 8
    case 'RC2-128-CBC': return 16
    default:
      throw new PBEError(
        `Unsupported encryption algorithm: ${algorithm}`,
        PBEErrorCode.UNSUPPORTED_ALGORITHM,
      )
  }
}

// Utility functions
function stringToBuffer(str: string): ByteStringBuffer {
  return createBuffer(str)
}

function bufferToString(buf: ByteStringBuffer): string {
  return buf.toString()
}
