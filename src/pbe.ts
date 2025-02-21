/**
 * Password-based encryption functions.
 *
 * @author Dave Longley
 * @author Stefan Siegl <stesie@brokenpipe.de>
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 * Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
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

import type { Asn1Object } from './asn1'
import type { BlockCipher } from './cipher'
import type { MessageDigest } from './sha1'
import { aes } from './aes'
import { asn1 } from './asn1'
import { createCipher } from './cipher'
import { des } from './des'
import { md5 } from './md5'
import { oids } from './oids'
import { pbkdf2 } from './pbkdf2'
import { getBytesSync } from './random'
import { rc2 } from './rc2'
import { sha512 } from './sha512'
import { ByteBuffer, createBuffer, hexToBytes } from './utils'

// validator for an EncryptedPrivateKeyInfo structure
// Note: Currently only works w/algorithm params
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
      capture: 'encryptionOid',
    }, {
      name: 'AlgorithmIdentifier.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'encryptionParams',
    }],
  }, {
    // encryptedData
    name: 'EncryptedPrivateKeyInfo.encryptedData',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'encryptedData',
  }],
}

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
export function encryptPrivateKeyInfo(obj: any, password: any, options: any): Buffer {
  // set default options
  options = options || {}
  options.saltSize = options.saltSize || 8
  options.count = options.count || 2048
  options.algorithm = options.algorithm || 'aes128'
  options.prfAlgorithm = options.prfAlgorithm || 'sha1'

  // generate PBE params
  const salt = getBytesSync(options.saltSize)
  const count = options.count
  const countBytes = asn1.integerToDer(count)
  let dkLen
  let encryptionAlgorithm
  let encryptedData
  if (options.algorithm.indexOf('aes') === 0 || options.algorithm === 'des') {
    // do PBES2
    let ivLen, encOid, cipherFn
    switch (options.algorithm) {
      case 'aes128':
        dkLen = 16
        ivLen = 16
        encOid = oids['aes128-CBC']
        cipherFn = createCipher('AES-CBC', getBytesSync(16))
        break
      case 'aes192':
        dkLen = 24
        ivLen = 16
        encOid = oids['aes192-CBC']
        cipherFn = createCipher('AES-CBC', getBytesSync(16))
        break
      case 'aes256':
        dkLen = 32
        ivLen = 16
        encOid = oids['aes256-CBC']
        cipherFn = createCipher('AES-CBC', getBytesSync(16))
        break
      case 'des':
        dkLen = 8
        ivLen = 8
        encOid = oids.desCBC
        cipherFn = createCipher('DES-CBC', getBytesSync(8))
        break
      default:
        const error = new Error('Cannot encrypt private key. Unknown encryption algorithm.')
        error.algorithm = options.algorithm
        throw error
    }

    // get PRF message digest
    const prfAlgorithm = `hmacWith${options.prfAlgorithm.toUpperCase()}`
    const md = prfAlgorithmToMessageDigest(prfAlgorithm)

    // encrypt private key using pbe SHA-1 and AES/DES
    var dk = pbkdf2(password, salt, count, dkLen, md)
    var iv = getBytesSync(ivLen)
    var cipher = cipherFn(dk)
    cipher.start(iv)
    cipher.update(asn1.toDer(obj))
    cipher.finish()
    encryptedData = cipher.output.getBytes()

    // get PBKDF2-params
    const params = createPbkdf2Params(salt, countBytes, dkLen, prfAlgorithm)

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

    const saltBytes = new ByteBuffer(salt)
    var dk = generatePkcs12Key(password, saltBytes, 1, count, dkLen)
    var iv = generatePkcs12Key(password, saltBytes, 2, count, dkLen)
    var cipher = des.createEncryptionCipher(dk)
    cipher.start(iv)
    cipher.update(asn1.toDer(obj))
    cipher.finish()
    encryptedData = cipher.output.getBytes()

    encryptionAlgorithm = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.SEQUENCE,
      true,
      [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids['pbeWithSHAAnd3-KeyTripleDES-CBC']).getBytes()),
        // pkcs-12PbeParams
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // salt
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, salt),
          // iteration count
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, countBytes.getBytes()),
        ]),
      ],
    )
  }
  else {
    const error = new Error('Cannot encrypt private key. Unknown encryption algorithm.')
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
pki.decryptPrivateKeyInfo = function (obj, password) {
  let rval = null

  // get PBE params
  const capture = {}
  const errors = []
  if (!asn1.validate(obj, encryptedPrivateKeyValidator, capture, errors)) {
    const error = new Error('Cannot read encrypted private key. '
      + 'ASN.1 object is not a supported EncryptedPrivateKeyInfo.')
    error.errors = errors
    throw error
  }

  // get cipher
  const oid = asn1.derToOid(capture.encryptionOid)
  const cipher = pki.pbe.getCipher(oid, capture.encryptionParams, password)

  // get encrypted data
  const encrypted = createBuffer(capture.encryptedData)

  cipher.update(encrypted)
  if (cipher.finish()) {
    rval = asn1.fromDer(cipher.output)
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
pki.encryptedPrivateKeyToPem = function (epki, maxline) {
  // convert to DER, then PEM-encode
  const msg = {
    type: 'ENCRYPTED PRIVATE KEY',
    body: asn1.toDer(epki).getBytes(),
  }
  return forge.pem.encode(msg, { maxline })
}

/**
 * Converts a PEM-encoded EncryptedPrivateKeyInfo to ASN.1 format. Decryption
 * is not performed.
 *
 * @param pem the EncryptedPrivateKeyInfo in PEM-format.
 *
 * @return the ASN.1 EncryptedPrivateKeyInfo.
 */
pki.encryptedPrivateKeyFromPem = function (pem) {
  const msg = forge.pem.decode(pem)[0]

  if (msg.type !== 'ENCRYPTED PRIVATE KEY') {
    const error = new Error('Could not convert encrypted private key from PEM; '
      + 'PEM header type is "ENCRYPTED PRIVATE KEY".')
    error.headerType = msg.type
    throw error
  }
  if (msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert encrypted private key from PEM; '
      + 'PEM is encrypted.')
  }

  // convert DER to ASN.1 object
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
 * @param options:
 *          algorithm: the encryption algorithm to use
 *            ('aes128', 'aes192', 'aes256', '3des', 'des').
 *          count: the iteration count to use.
 *          saltSize: the salt size to use.
 *          legacy: output an old non-PKCS#8 PEM-encrypted+encapsulated
 *            headers (DEK-Info) private key.
 *
 * @return the PEM-encoded ASN.1 EncryptedPrivateKeyInfo.
 */
pki.encryptRsaPrivateKey = function (rsaKey, password, options) {
  // standard PKCS#8
  options = options || {}
  if (!options.legacy) {
    // encrypt PrivateKeyInfo
    let rval = pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(rsaKey))
    rval = pki.encryptPrivateKeyInfo(rval, password, options)
    return pki.encryptedPrivateKeyToPem(rval)
  }

  // legacy non-PKCS#8
  let algorithm
  let iv
  let dkLen
  let cipherFn
  switch (options.algorithm) {
    case 'aes128':
      algorithm = 'AES-128-CBC'
      dkLen = 16
      iv = getBytesSync(16)
      cipherFn = aes.createEncryptionCipher
      break
    case 'aes192':
      algorithm = 'AES-192-CBC'
      dkLen = 24
      iv = getBytesSync(16)
      cipherFn = aes.createEncryptionCipher
      break
    case 'aes256':
      algorithm = 'AES-256-CBC'
      dkLen = 32
      iv = getBytesSync(16)
      cipherFn = aes.createEncryptionCipher
      break
    case '3des':
      algorithm = 'DES-EDE3-CBC'
      dkLen = 24
      iv = getBytesSync(8)
      cipherFn = des.createEncryptionCipher
      break
    case 'des':
      algorithm = 'DES-CBC'
      dkLen = 8
      iv = getBytesSync(8)
      cipherFn = des.createEncryptionCipher
      break
    default:
      var error = new Error(`Could not encrypt RSA private key; unsupported `
        + `encryption algorithm "${options.algorithm}".`)
      error.algorithm = options.algorithm
      throw error
  }

  // encrypt private key using OpenSSL legacy key derivation
  const dk = opensslDeriveBytes(password, iv.substr(0, 8), dkLen)
  const cipher = cipherFn(dk)
  cipher.start(iv)
  cipher.update(asn1.toDer(pki.privateKeyToAsn1(rsaKey)))
  cipher.finish()

  const msg = {
    type: 'RSA PRIVATE KEY',
    procType: {
      version: '4',
      type: 'ENCRYPTED',
    },
    dekInfo: {
      algorithm,
      parameters: forge.util.bytesToHex(iv).toUpperCase(),
    },
    body: cipher.output.getBytes(),
  }
  return forge.pem.encode(msg)
}

/**
 * Decrypts an RSA private key.
 *
 * @param pem the PEM-formatted EncryptedPrivateKeyInfo to decrypt.
 * @param password the password to use.
 *
 * @return the RSA key on success, null on failure.
 */
pki.decryptRsaPrivateKey = function (pem, password) {
  let rval = null

  const msg = forge.pem.decode(pem)[0]

  if (msg.type !== 'ENCRYPTED PRIVATE KEY'
    && msg.type !== 'PRIVATE KEY'
    && msg.type !== 'RSA PRIVATE KEY') {
    var error = new Error('Could not convert private key from PEM; PEM header type '
      + 'is not "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", or "RSA PRIVATE KEY".')
    error.headerType = error
    throw error
  }

  if (msg.procType && msg.procType.type === 'ENCRYPTED') {
    let dkLen
    let cipherFn
    switch (msg.dekInfo.algorithm) {
      case 'DES-CBC':
        dkLen = 8
        cipherFn = des.createDecryptionCipher
        break
      case 'DES-EDE3-CBC':
        dkLen = 24
        cipherFn = des.createDecryptionCipher
        break
      case 'AES-128-CBC':
        dkLen = 16
        cipherFn = aes.createDecryptionCipher
        break
      case 'AES-192-CBC':
        dkLen = 24
        cipherFn = aes.createDecryptionCipher
        break
      case 'AES-256-CBC':
        dkLen = 32
        cipherFn = aes.createDecryptionCipher
        break
      case 'RC2-40-CBC':
        dkLen = 5
        cipherFn = function (key) {
          return rc2.createDecryptionCipher(key, 40)
        }
        break
      case 'RC2-64-CBC':
        dkLen = 8
        cipherFn = function (key) {
          return forge.rc2.createDecryptionCipher(key, 64)
        }
        break
      case 'RC2-128-CBC':
        dkLen = 16
        cipherFn = function (key) {
          return forge.rc2.createDecryptionCipher(key, 128)
        }
        break
      default:
        var error = new Error(`Could not decrypt private key; unsupported `
          + `encryption algorithm "${msg.dekInfo.algorithm}".`)
        error.algorithm = msg.dekInfo.algorithm
        throw error
    }

    // use OpenSSL legacy key derivation
    const iv = hexToBytes(msg.dekInfo.parameters)
    const dk = opensslDeriveBytes(password, iv.substr(0, 8), dkLen)
    const cipher = cipherFn(dk)
    cipher.start(iv)
    cipher.update(createBuffer(msg.body))
    if (cipher.finish()) {
      rval = cipher.output.getBytes()
    }
    else {
      return rval
    }
  }
  else {
    rval = msg.body
  }

  if (msg.type === 'ENCRYPTED PRIVATE KEY') {
    rval = pki.decryptPrivateKeyInfo(asn1.fromDer(rval), password)
  }
  else {
    // decryption already performed above
    rval = asn1.fromDer(rval)
  }

  if (rval !== null) {
    rval = pki.privateKeyFromAsn1(rval)
  }

  return rval
}

/**
 * Derives a PKCS#12 key.
 *
 * @param password the password to derive the key material from, null or
 *          undefined for none.
 * @param salt the salt, as a ByteBuffer, to use.
 * @param id the PKCS#12 ID byte (1 = key material, 2 = IV, 3 = MAC).
 * @param iter the iteration count.
 * @param n the number of bytes to derive from the password.
 * @param md the message digest to use, defaults to SHA-1.
 *
 * @return a ByteBuffer with the bytes derived from the password.
 */
export function generatePkcs12Key(password: string, salt: string, id: number, iter: number, n: number, md: any): ByteBuffer {
  let j, l

  if (typeof md === 'undefined' || md === null) {
    if (!('sha1' in forge.md)) {
      throw new Error('"sha1" hash algorithm unavailable.')
    }
    md = forge.md.sha1.create()
  }

  const u = md.digestLength
  const v = md.blockLength
  const result = new ByteBuffer()

  /* Convert password to Unicode byte buffer + trailing 0-byte. */
  const passBuf = new ByteBuffer()
  if (password !== null && password !== undefined) {
    for (l = 0; l < password.length; l++) {
      passBuf.putInt16(password.charCodeAt(l))
    }
    passBuf.putInt16(0)
  }

  /* Length of salt and password in BYTES. */
  const p = passBuf.length()
  const s = salt.length()

  /* 1. Construct a string, D (the "diversifier"), by concatenating
        v copies of ID. */
  const D = new ByteBuffer()
  D.fillWithByte(id, v)

  /* 2. Concatenate copies of the salt together to create a string S of length
        v * ceil(s / v) bytes (the final copy of the salt may be trunacted
        to create S).
        Note that if the salt is the empty string, then so is S. */
  const Slen = v * Math.ceil(s / v)
  const S = new ByteBuffer()
  for (l = 0; l < Slen; l++) {
    S.putByte(salt.at(l % s))
  }

  /* 3. Concatenate copies of the password together to create a string P of
        length v * ceil(p / v) bytes (the final copy of the password may be
        truncated to create P).
        Note that if the password is the empty string, then so is P. */
  const Plen = v * Math.ceil(p / v)
  const P = new ByteBuffer()
  for (l = 0; l < Plen; l++) {
    P.putByte(passBuf.at(l % p))
  }

  /* 4. Set I=S||P to be the concatenation of S and P. */
  let I = S
  I.putBuffer(P)

  /* 5. Set c=ceil(n / u). */
  const c = Math.ceil(n / u)

  /* 6. For i=1, 2, ..., c, do the following: */
  for (let i = 1; i <= c; i++) {
    /* a) Set Ai=H^r(D||I). (l.e. the rth hash of D||I, H(H(H(...H(D||I)))) */
    let buf = new ByteBuffer()
    buf.putBytes(D.bytes())
    buf.putBytes(I.bytes())
    for (let round = 0; round < iter; round++) {
      md.start()
      md.update(buf.getBytes())
      buf = md.digest()
    }

    /* b) Concatenate copies of Ai to create a string B of length v bytes (the
          final copy of Ai may be truncated to create B). */
    const B = new ByteBuffer()
    for (l = 0; l < v; l++) {
      B.putByte(buf.at(l % u))
    }

    /* c) Treating I as a concatenation I0, I1, ..., Ik-1 of v-byte blocks,
          where k=ceil(s / v) + ceil(p / v), modify I by setting
          Ij=(Ij+B+1) mod 2v for each j.  */
    const k = Math.ceil(s / v) + Math.ceil(p / v)
    const Inew = new ByteBuffer()
    for (j = 0; j < k; j++) {
      const chunk = new ByteBuffer(I.getBytes(v))
      let x = 0x1FF
      for (l = B.length() - 1; l >= 0; l--) {
        x = x >> 8
        x += B.at(l) + chunk.at(l)
        chunk.setAt(l, x & 0xFF)
      }
      Inew.putBuffer(chunk)
    }
    I = Inew

    /* Add Ai to A. */
    result.putBuffer(buf)
  }

  result.truncate(result.length() - n)
  return result
}

/**
 * Get new Forge cipher object instance.
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
      var error = new Error('Cannot read encrypted PBE data block. Unsupported OID.')
      error.oid = oid
      error.supportedOids = [
        'pkcs5PBES2',
        'pbeWithSHAAnd3-KeyTripleDES-CBC',
        'pbewithSHAAnd40BitRC2-CBC',
      ]
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
  const capture = {}
  const errors = []

  if (!asn1.validate(params, PBES2AlgorithmsValidator, capture, errors)) {
    var error = new Error('Cannot read password-based-encryption algorithm '
      + 'parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo.')
    error.errors = errors
    throw error
  }

  // check oids
  oid = asn1.derToOid(capture.kdfOid)
  if (oid !== oids.pkcs5PBKDF2) {
    var error = new Error('Cannot read encrypted private key. '
      + 'Unsupported key derivation function OID.')
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
    var error = new Error('Cannot read encrypted private key. '
      + 'Unsupported encryption scheme OID.')
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
  let count = createBuffer(capture.kdfIterationCount)
  count = count.getInt(count.length() << 3)
  let dkLen
  let cipherFn

  switch (oids[oid]) {
    case 'aes128-CBC':
      dkLen = 16
      cipherFn = createCipher('AES-CBC', key)
      break
    case 'aes192-CBC':
      dkLen = 24
      cipherFn = createCipher('AES-CBC', key)
      break
    case 'aes256-CBC':
      dkLen = 32
      cipherFn = createCipher('AES-CBC', key)
      break
    case 'des-EDE3-CBC':
      dkLen = 24
      cipherFn = createCipher('3DES-CBC', key)
      break
    case 'desCBC':
      dkLen = 8
      cipherFn = createCipher('DES-CBC', key)
      break
  }

  // get PRF message digest
  const md = prfOidToMessageDigest(capture.prfOid)

  // decrypt private key using pbe with chosen PRF and AES/DES
  const dk = pbkdf2(password, salt, count, dkLen, md)
  const iv = capture.encIv
  const cipher = cipherFn(dk)
  cipher.start(iv)

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
  const errors = []

  if (!asn1.validate(params, pkcs12PbeParamsValidator, capture, errors)) {
    var error = new Error('Cannot read password-based-encryption algorithm '
      + 'parameters. ASN.1 object is not a supported EncryptedPrivateKeyInfo.')
    error.errors = errors
    throw error
  }

  const salt = createBuffer(capture.salt)
  let count = createBuffer(capture.iterations)
  count = count.getInt(count.length() << 3)

  let dkLen, dIvLen, cipherFn
  switch (oid) {
    case oids['pbeWithSHAAnd3-KeyTripleDES-CBC']:
      dkLen = 24
      dIvLen = 8
      cipherFn = des.startDecrypting
      break

    case oids['pbewithSHAAnd40BitRC2-CBC']:
      dkLen = 5
      dIvLen = 8
      cipherFn = function (key, iv) {
        const cipher = rc2.createDecryptionCipher(key, 40)
        cipher.start(iv, null)
        return cipher
      }
      break

    default:
      var error = new Error('Cannot read PKCS #12 PBE data block. Unsupported OID.')
      error.oid = oid
      throw error
  }

  // get PRF message digest
  const md = prfOidToMessageDigest(capture.prfOid)
  const key = pki.pbe.generatePkcs12Key(password, salt, 1, count, dkLen, md)
  md.start()
  const iv = pki.pbe.generatePkcs12Key(password, salt, 2, count, dIvLen, md)

  return cipherFn(key, iv)
}

/**
 * OpenSSL's legacy key derivation function.
 *
 * See: http://www.openssl.org/docs/crypto/EVP_BytesToKey.html
 *
 * @param password the password to derive the key from.
 * @param salt the salt to use, null for none.
 * @param dkLen the number of bytes needed for the derived key.
 * @param [options] the options to use:
 *          [md] an optional message digest object to use.
 */
export function opensslDeriveBytes(password: string, salt: string, dkLen: number, md: any): string {
  if (typeof md === 'undefined' || md === null) {
    if (!('md5' in md)) {
      throw new Error('"md5" hash algorithm unavailable.')
    }

    md = md5.create()
  }

  if (salt === null) {
    salt = ''
  }

  const digests = [hash(md, password + salt)]

  for (let length = 16, i = 1; length < dkLen; ++i, length += 16)
    digests.push(hash(md, digests[i - 1] + password + salt))

  return digests.join('').substr(0, dkLen)
}

export function hash(md: MessageDigest, bytes: string): string {
  return md.start().update(bytes).digest().getBytes()
}

export function prfOidToMessageDigest(prfOid: string): MessageDigest {
  // get PRF algorithm, default to SHA-1
  let prfAlgorithm

  if (!prfOid) {
    prfAlgorithm = 'hmacWithSHA1'
  }

  else {
    prfAlgorithm = oids[asn1.derToOid(prfOid)]
    if (!prfAlgorithm) {
      const error = new Error('Unsupported PRF OID.')
      error.oid = prfOid
      error.supported = [
        'hmacWithSHA1',
        'hmacWithSHA224',
        'hmacWithSHA256',
        'hmacWithSHA384',
        'hmacWithSHA512',
      ]
      throw error
    }
  }
  return prfAlgorithmToMessageDigest(prfAlgorithm)
}

export function prfAlgorithmToMessageDigest(prfAlgorithm: string): MessageDigest {
  let factory

  switch (prfAlgorithm) {
    case 'hmacWithSHA224':
      factory = sha512
    case 'hmacWithSHA1':
    case 'hmacWithSHA256':
    case 'hmacWithSHA384':
    case 'hmacWithSHA512':
      prfAlgorithm = prfAlgorithm.substr(8).toLowerCase()
      break
    default:
      var error = new Error('Unsupported PRF algorithm.')
      error.algorithm = prfAlgorithm
      error.supported = [
        'hmacWithSHA1',
        'hmacWithSHA224',
        'hmacWithSHA256',
        'hmacWithSHA384',
        'hmacWithSHA512',
      ]
      throw error
  }
  if (!factory || !(prfAlgorithm in factory)) {
    throw new Error(`Unknown hash algorithm: ${prfAlgorithm}`)
  }
  return factory[prfAlgorithm].create()
}

export function createPbkdf2Params(salt: string, countBytes: Buffer, dkLen: number, prfAlgorithm: string): Asn1Object {
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
