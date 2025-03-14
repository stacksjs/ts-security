import type { ByteStringBuffer } from 'ts-security-utils'
import { bytesToHex, createBuffer, decodeUtf8 } from 'ts-security-utils'
import { oids } from '../../oids'

/**
 * TypeScript implementation of Abstract Syntax Notation Number One.
 *
 * @author Dave Longley
 * @author Chris Breuer
 *
 * An API for storing data using the Abstract Syntax Notation Number One
 * format using DER (Distinguished Encoding Rules) encoding. This encoding is
 * commonly used to store data for PKI, i.e. X.509 Certificates, and this
 * implementation exists for that purpose.
 *
 * Abstract Syntax Notation Number One (ASN.1) is used to define the abstract
 * syntax of information without restricting the way the information is encoded
 * for transmission. It provides a standard that allows for open systems
 * communication. ASN.1 defines the syntax of information data and a number of
 * simple data types as well as a notation for describing them and specifying
 * values for them.
 *
 * The RSA algorithm creates public and private keys that are often stored in
 * X.509 or PKCS#X formats -- which use ASN.1 (encoded in DER format). This
 * class provides the most basic functionality required to store and load DSA
 * keys that are encoded according to ASN.1.
 *
 * The most common binary encodings for ASN.1 are BER (Basic Encoding Rules)
 * and DER (Distinguished Encoding Rules). DER is just a subset of BER that
 * has stricter requirements for how data must be encoded.
 *
 * Each ASN.1 structure has a tag (a byte identifying the ASN.1 structure type)
 * and a byte array for the value of this ASN1 structure which may be data or a
 * list of ASN.1 structures.
 *
 * Each ASN.1 structure using BER is (Tag-Length-Value):
 *
 * | byte 0 | bytes X | bytes Y |
 * |--------|---------|----------
 * |  tag   | length  |  value  |
 *
 * ASN.1 allows for tags to be of "High-tag-number form" which allows a tag to
 * be two or more octets, but that is not supported by this class. A tag is
 * only 1 byte. Bits 1-5 give the tag number (ie the data type within a
 * particular 'class'), 6 indicates whether or not the ASN.1 value is
 * constructed from other ASN.1 values, and bits 7 and 8 give the 'class'. If
 * bits 7 and 8 are both zero, the class is UNIVERSAL. If only bit 7 is set,
 * then the class is APPLICATION. If only bit 8 is set, then the class is
 * CONTEXT_SPECIFIC. If both bits 7 and 8 are set, then the class is PRIVATE.
 * The tag numbers for the data types for the class UNIVERSAL are listed below:
 *
 * UNIVERSAL 0 Reserved for use by the encoding rules
 * UNIVERSAL 1 Boolean type
 * UNIVERSAL 2 Integer type
 * UNIVERSAL 3 Bitstring type
 * UNIVERSAL 4 Octetstring type
 * UNIVERSAL 5 Null type
 * UNIVERSAL 6 Object identifier type
 * UNIVERSAL 7 Object descriptor type
 * UNIVERSAL 8 External type and Instance-of type
 * UNIVERSAL 9 Real type
 * UNIVERSAL 10 Enumerated type
 * UNIVERSAL 11 Embedded-pdv type
 * UNIVERSAL 12 UTF8String type
 * UNIVERSAL 13 Relative object identifier type
 * UNIVERSAL 14-15 Reserved for future editions
 * UNIVERSAL 16 Sequence and Sequence-of types
 * UNIVERSAL 17 Set and Set-of types
 * UNIVERSAL 18-22, 25-30 Character string types
 * UNIVERSAL 23-24 Time types
 *
 * The length of an ASN.1 structure is specified after the tag identifier.
 * There is a definite form and an indefinite form. The indefinite form may
 * be used if the encoding is constructed and not all immediately available.
 * The indefinite form is encoded using a length byte with only the 8th bit
 * set. The end of the constructed object is marked using end-of-contents
 * octets (two zero bytes).
 *
 * The definite form looks like this:
 *
 * The length may take up 1 or more bytes, it depends on the length of the
 * value of the ASN.1 structure. DER encoding requires that if the ASN.1
 * structure has a value that has a length greater than 127, more than 1 byte
 * will be used to store its length, otherwise just one byte will be used.
 * This is strict.
 *
 * In the case that the length of the ASN.1 value is less than 127, 1 octet
 * (byte) is used to store the "short form" length. The 8th bit has a value of
 * 0 indicating the length is "short form" and not "long form" and bits 7-1
 * give the length of the data. (The 8th bit is the left-most, most significant
 * bit: also known as big endian or network format).
 *
 * In the case that the length of the ASN.1 value is greater than 127, 2 to
 * 127 octets (bytes) are used to store the "long form" length. The first
 * byte's 8th bit is set to 1 to indicate the length is "long form." Bits 7-1
 * give the number of additional octets. All following octets are in base 256
 * with the most significant digit first (typical big-endian binary unsigned
 * integer storage). So, for instance, if the length of a value was 257, the
 * first byte would be set to:
 *
 * 10000010 = 130 = 0x82.
 *
 * This indicates there are 2 octets (base 256) for the length. The second and
 * third bytes (the octets just mentioned) would store the length in base 256:
 *
 * octet 2: 00000001 = 1 * 256^1 = 256
 * octet 3: 00000001 = 1 * 256^0 = 1
 * total = 257
 *
 * The algorithm for converting a js integer value of 257 to base-256 is:
 *
 * var value = 257;
 * var bytes = [];
 * bytes[0] = (value >>> 8) & 0xFF; // most significant byte first
 * bytes[1] = value & 0xFF;        // least significant byte last
 *
 * On the ASN.1 UNIVERSAL Object Identifier (OID) type:
 *
 * An OID can be written like: "value1.value2.value3...valueN"
 *
 * The DER encoding rules:
 *
 * The first byte has the value 40 * value1 + value2.
 * The following bytes, if any, encode the remaining values. Each value is
 * encoded in base 128, most significant digit first (big endian), with as
 * few digits as possible, and the most significant bit of each byte set
 * to 1 except the last in each value's encoding. For example: Given the
 * OID "1.2.840.113549", its DER encoding is (remember each byte except the
 * last one in each encoding is OR'd with 0x80):
 *
 * byte 1: 40 * 1 + 2 = 42 = 0x2A.
 * bytes 2-3: 128 * 6 + 72 = 840 = 6 72 = 6 72 = 0x0648 = 0x8648
 * bytes 4-6: 16384 * 6 + 128 * 119 + 13 = 6 119 13 = 0x06770D = 0x86F70D
 *
 * The final value is: 0x2A864886F70D.
 * The full OID (including ASN.1 tag and length of 6 bytes) is:
 * 0x06062A864886F70D
 */

interface ExtendedError extends Error {
  available?: number
  remaining?: number
  requested?: number
  byteCount?: number
  integer?: number
}

export interface Asn1Object {
  name?: string
  tagClass: number
  type: number
  constructed: boolean
  composed?: boolean
  captureAsn1?: string
  value: any
  bitStringContents?: string
  original?: Asn1Object
}

interface CreateOptions {
  bitStringContents?: string
}

interface DerOptions {
  strict?: boolean
  parseAllBytes?: boolean
  decodeBitStrings?: boolean
}

/**
 * ASN.1 classes.
 */
export const Class = {
  UNIVERSAL: 0x00,
  APPLICATION: 0x40,
  CONTEXT_SPECIFIC: 0x80,
  PRIVATE: 0xC0,
  SEQUENCE: 0x10,
  SET: 0x11,
  INTEGER: 0x02,
} as const

/**
 * ASN.1 types. Not all types are supported by this implementation, only
 * those necessary to implement a simple PKI are implemented.
 */
export const Type = {
  NONE: 0,
  BOOLEAN: 1,
  INTEGER: 2,
  BITSTRING: 3,
  OCTETSTRING: 4,
  NULL: 5,
  OID: 6,
  ODESC: 7,
  EXTERNAL: 8,
  REAL: 9,
  ENUMERATED: 10,
  EMBEDDED: 11,
  UTF8: 12,
  ROID: 13,
  SEQUENCE: 16,
  SET: 17,
  PRINTABLESTRING: 19,
  IA5STRING: 22,
  UTCTIME: 23,
  GENERALIZEDTIME: 24,
  BMPSTRING: 30,
} as const

/**
 * Creates a new asn1 object.
 *
 * @param tagClass the tag class for the object.
 * @param type the data type (tag number) for the object.
 * @param constructed true if the asn1 object is in constructed form.
 * @param value the value for the object, if it is not constructed.
 * @param options the options to use:
 * @param options.bitStringContents the plain BIT STRING content including padding byte.
 *
 * @return the asn1 object.
 */
export function createAsn1Object(tagClass: number, type: number, constructed: boolean, value: any, options?: CreateOptions): Asn1Object {
  /* An asn1 object has a tagClass, a type, a constructed flag, and a
    value. The value's type depends on the constructed flag. If
    constructed, it will contain a list of other asn1 objects. If not,
    it will contain the ASN.1 value as an array of bytes formatted
    according to the ASN.1 data type. */

  // remove undefined values
  if (Array.isArray(value)) {
    const tmp = []
    for (let i = 0; i < value.length; ++i) {
      if (value[i] !== undefined) {
        tmp.push(value[i])
      }
    }
    value = tmp
  }

  const obj: Asn1Object = {
    tagClass,
    type,
    constructed,
    composed: constructed || Array.isArray(value),
    value,
  }
  if (options && 'bitStringContents' in options) {
    obj.bitStringContents = options.bitStringContents
    // save copy to detect changes
    const original = copy(obj, { excludeBitStringContents: true })
    if (typeof original !== 'string' && !Array.isArray(original)) {
      obj.original = original
    }
  }
  return obj
}

/**
 * Copies an asn1 object.
 *
 * @param obj the asn1 object.
 * @param [options] copy options:
 *          [excludeBitStringContents] true to not copy bitStringContents
 *
 * @return the a copy of the asn1 object.
 */
export function copy(obj: Asn1Object | any[] | string, options?: { excludeBitStringContents?: boolean }): Asn1Object | any[] | string {
  if (Array.isArray(obj)) {
    const copy = []
    for (let i = 0; i < obj.length; ++i) {
      copy.push(asn1.copy(obj[i], options))
    }
    return copy
  }

  if (typeof obj === 'string') {
    return obj
  }

  // At this point obj must be Asn1Object
  const asn1Obj = obj as Asn1Object
  const copy: Asn1Object = {
    tagClass: asn1Obj.tagClass,
    type: asn1Obj.type,
    constructed: asn1Obj.constructed,
    composed: asn1Obj.composed,
    value: asn1.copy(asn1Obj.value, options),
  }
  if (options && !options.excludeBitStringContents && asn1Obj.bitStringContents) {
    copy.bitStringContents = asn1Obj.bitStringContents
  }

  return copy
}

/**
 * Compares asn1 objects for equality.
 *
 * Note this function does not run in constant time.
 *
 * @param obj1 the first asn1 object.
 * @param obj2 the second asn1 object.
 * @param [options] compare options:
 *          [includeBitStringContents] true to compare bitStringContents
 *
 * @return true if the asn1 objects are equal.
 */
export function equals(obj1: Asn1Object | any[] | string, obj2: Asn1Object | any[] | string, options?: { includeBitStringContents?: boolean }): boolean {
  if (Array.isArray(obj1)) {
    if (!Array.isArray(obj2))
      return false

    if (obj1.length !== obj2.length)
      return false

    for (let i = 0; i < obj1.length; ++i) {
      if (!asn1.equals(obj1[i], obj2[i], options))
        return false
    }

    return true
  }

  if (typeof obj1 !== typeof obj2)
    return false

  if (typeof obj1 === 'string')
    return obj1 === obj2

  // At this point both obj1 and obj2 must be Asn1Object
  const asn1Obj1 = obj1 as Asn1Object
  const asn1Obj2 = obj2 as Asn1Object

  let equal = asn1Obj1.tagClass === asn1Obj2.tagClass
    && asn1Obj1.type === asn1Obj2.type
    && asn1Obj1.constructed === asn1Obj2.constructed
    && asn1Obj1.composed === asn1Obj2.composed
    && asn1.equals(asn1Obj1.value, asn1Obj2.value, options)

  if (options && options.includeBitStringContents) {
    equal = equal && (asn1Obj1.bitStringContents === asn1Obj2.bitStringContents)
  }

  return equal
}

/**
 * Gets the length of a BER-encoded ASN.1 value.
 *
 * In case the length is not specified, undefined is returned.
 *
 * @param b the BER-encoded ASN.1 byte buffer, starting with the first
 *          length byte.
 *
 * @return the length of the BER-encoded ASN.1 value or undefined.
 */
export function getBerValueLength(b: any): number | undefined {
  // TODO: move this function and related DER/BER functions to a der.js
  // file; better abstract ASN.1 away from der/ber.
  const b2 = b.getByte()
  if (b2 === 0x80) {
    return undefined
  }

  // see if the length is "short form" or "long form" (bit 8 set)
  let length
  const longForm = b2 & 0x80
  if (!longForm) {
    // length is just the first byte
    length = b2
  }
  else {
    // the number of bytes the length is specified in bits 7 through 1
    // and each length byte is in big-endian base-256
    length = b.getInt((b2 & 0x7F) << 3)
  }

  return length
}

/**
 * Check if the byte buffer has enough bytes. Throws an Error if not.
 *
 * @param bytes the byte buffer to parse from.
 * @param remaining the bytes remaining in the current parsing state.
 * @param n the number of bytes the buffer must have.
 */
function _checkBufferLength(bytes: ByteStringBuffer, remaining: number, n: number): void {
  if (n > remaining) {
    const error = new Error('Too few bytes to parse DER.') as ExtendedError
    error.available = bytes.length()
    error.remaining = remaining
    error.requested = n
    throw error
  }
}

/**
 * Gets the length of a BER-encoded ASN.1 value.
 *
 * In case the length is not specified, undefined is returned.
 *
 * @param bytes the byte buffer to parse from.
 * @param remaining the bytes remaining in the current parsing state.
 *
 * @return the length of the BER-encoded ASN.1 value or undefined.
 */
function _getValueLength(bytes: any, remaining: number): number | undefined {
  // TODO: move this function and related DER/BER functions to a der.js
  // file; better abstract ASN.1 away from der/ber.
  // fromDer already checked that this byte exists
  const b2 = bytes.getByte()
  remaining--
  if (b2 === 0x80) {
    return undefined
  }

  // see if the length is "short form" or "long form" (bit 8 set)
  let length
  const longForm = b2 & 0x80
  if (!longForm) {
    // length is just the first byte
    length = b2
  }
  else {
    // the number of bytes the length is specified in bits 7 through 1
    // and each length byte is in big-endian base-256
    const longFormBytes = b2 & 0x7F
    _checkBufferLength(bytes, remaining, longFormBytes)
    length = bytes.getInt(longFormBytes << 3)
  }
  // FIXME: this will only happen for 32 bit getInt with high bit set
  if (length < 0) {
    throw new Error(`Negative length: ${length}`)
  }
  return length
}

/**
 * Parses an asn1 object from a byte buffer in DER format.
 *
 * @param bytes the byte buffer to parse from.
 * @param [strict] true to be strict when checking value lengths, false to
 *          allow truncated values (default: true).
 * @param [options] object with options or boolean strict flag
 *          [strict] true to be strict when checking value lengths, false to
 *            allow truncated values (default: true).
 *          [parseAllBytes] true to ensure all bytes are parsed
 *            (default: true)
 *          [decodeBitStrings] true to attempt to decode the content of
 *            BIT STRINGs (not OCTET STRINGs) using strict mode. Note that
 *            without schema support to understand the data context this can
 *            erroneously decode values that happen to be valid ASN.1. This
 *            flag will be deprecated or removed as soon as schema support is
 *            available. (default: true)
 *
 * @throws Will throw an error for various malformed input conditions.
 *
 * @return the parsed asn1 object.
 */
export function fromDer(bytes: ByteStringBuffer | string, options?: DerOptions | boolean): Asn1Object {
  const opts: DerOptions = {
    strict: true,
    parseAllBytes: true,
    decodeBitStrings: true,
  }

  if (typeof options === 'boolean') {
    opts.strict = options
  }
  else if (options) {
    Object.assign(opts, options)
  }

  // wrap in buffer if needed
  const buffer = typeof bytes === 'string' ? createBuffer(bytes) : bytes

  const byteCount = buffer.length()
  const value = _fromDer(buffer, buffer.length(), 0, opts)
  if (opts.parseAllBytes && buffer.length() !== 0) {
    const error = new Error('Unparsed DER bytes remain after ASN.1 parsing.') as ExtendedError
    error.byteCount = byteCount
    error.remaining = buffer.length()
    throw error
  }
  return value
}

/**
 * Internal function to parse an asn1 object from a byte buffer in DER format.
 *
 * @param bytes the byte buffer to parse from.
 * @param remaining the number of bytes remaining for this chunk.
 * @param depth the current parsing depth.
 * @param options object with same options as fromDer().
 *
 * @return the parsed asn1 object.
 */
function _fromDer(bytes: ByteStringBuffer, remaining: number, depth: number, options: DerOptions): Asn1Object {
  // temporary storage for consumption calculations
  let start

  // minimum length for ASN.1 DER structure is 2
  _checkBufferLength(bytes, remaining, 2)

  // get the first byte
  const b1 = bytes.getByte()
  // consumed one byte
  remaining--

  // get the tag class
  const tagClass = (b1 & 0xC0)

  // get the type (bits 1-5)
  const type = b1 & 0x1F

  // get the variable value length and adjust remaining bytes
  start = bytes.length()
  let length = _getValueLength(bytes, remaining)
  remaining -= start - bytes.length()

  // ensure there are enough bytes to get the value
  if (length !== undefined && length > remaining) {
    if (options.strict) {
      const error = new Error('Too few bytes to read ASN.1 value.') as ExtendedError
      error.available = bytes.length()
      error.remaining = remaining
      error.requested = length
      throw error
    }
    // Note: be lenient with truncated values and use remaining state bytes
    length = remaining
  }

  // value storage
  let value
  // possible BIT STRING contents storage
  let bitStringContents: string | undefined

  // constructed flag is bit 6 (32 = 0x20) of the first byte
  const constructed = ((b1 & 0x20) === 0x20)
  if (constructed) {
    // parse child asn1 objects from the value
    value = []
    if (length === undefined) {
      // asn1 object of indefinite length, read until end tag
      for (; ;) {
        _checkBufferLength(bytes, remaining, 2)
        if (bytes.bytes(2) === String.fromCharCode(0, 0)) {
          bytes.getBytes(2)
          remaining -= 2
          break
        }
        start = bytes.length()
        value.push(_fromDer(bytes, remaining, depth + 1, options))
        remaining -= start - bytes.length()
      }
    }
    else {
      // parsing asn1 object of definite length
      while (length > 0) {
        start = bytes.length()
        value.push(_fromDer(bytes, length, depth + 1, options))
        remaining -= start - bytes.length()
        length -= start - bytes.length()
      }
    }
  }

  // if a BIT STRING, save the contents including padding
  if (value === undefined && tagClass === asn1.Class.UNIVERSAL
    && type === asn1.Type.BITSTRING) {
    bitStringContents = bytes.bytes(length || 0)
  }

  // determine if a non-constructed value should be decoded as a composed
  // value that contains other ASN.1 objects. BIT STRINGs (and OCTET STRINGs)
  // can be used this way.
  if (value === undefined && options.decodeBitStrings
    && tagClass === asn1.Class.UNIVERSAL
    && type === asn1.Type.BITSTRING
    && (length || 0) > 1) {
    // save read position
    const savedRead = bytes.length()
    const savedRemaining = remaining
    let unused = 0

    if (type === asn1.Type.BITSTRING) {
      _checkBufferLength(bytes, remaining, 1)
      unused = bytes.getByte()
      remaining--
    }

    // if all bits are used, maybe the BIT/OCTET STRING holds ASN.1 objs
    if (unused === 0) {
      try {
        // attempt to parse child asn1 object from the value
        // (stored in array to signal composed value)
        start = bytes.length()
        const subOptions = {
          // enforce strict mode to avoid parsing ASN.1 from plain data
          strict: true,
          decodeBitStrings: true,
        }
        const composed = _fromDer(bytes, remaining, depth + 1, subOptions)
        let used = start - bytes.length()
        remaining -= used
        if (type == asn1.Type.BITSTRING) {
          used++
        }

        // if the data all decoded and the class indicates UNIVERSAL or
        // CONTEXT_SPECIFIC then assume we've got an encapsulated ASN.1 object
        const tc = composed.tagClass
        if (used === length
          && (tc === asn1.Class.UNIVERSAL || tc === asn1.Class.CONTEXT_SPECIFIC)) {
          value = [composed]
        }
      }
      catch (ex) {
      }
    }
    if (value === undefined) {
      // restore read position
      bytes.read = savedRead
      remaining = savedRemaining
    }
  }

  if (value === undefined) {
    // asn1 not constructed or composed, get raw value
    // TODO: do DER to OID conversion and vice-versa in .toDer?

    if (length === undefined) {
      if (options.strict) {
        throw new Error('Non-constructed ASN.1 object of indefinite length.')
      }
      // be lenient and use remaining state bytes
      length = remaining
    }

    if (type === asn1.Type.BMPSTRING) {
      value = ''
      for (; length > 0; length -= 2) {
        _checkBufferLength(bytes, remaining, 2)
        value += String.fromCharCode(bytes.getInt16())
        remaining -= 2
      }
    }
    else {
      value = bytes.getBytes(length)
      remaining -= length
    }
  }

  // create and return asn1 object
  const asn1Options = bitStringContents !== undefined ? { bitStringContents } : undefined
  return asn1.create(tagClass, type, constructed, value, asn1Options)
}

/**
 * Converts the given asn1 object to a buffer of bytes in DER format.
 *
 * @param asn1 the asn1 object to convert to bytes.
 *
 * @return the buffer of bytes.
 */
export function toDer(obj: Asn1Object): ByteStringBuffer {
  const bytes = createBuffer()

  // build the first byte
  let b1 = obj.tagClass | obj.type

  // for storing the ASN.1 value
  const value = createBuffer()

  // use BIT STRING contents if available and data not changed
  let useBitStringContents = false
  if ('bitStringContents' in obj) {
    useBitStringContents = true
    if (obj.original) {
      useBitStringContents = asn1.equals(obj, obj.original, { includeBitStringContents: true })
    }
  }

  if (useBitStringContents && obj.bitStringContents) {
    value.putBytes(obj.bitStringContents)
  }
  else if (obj.composed) {
    // if composed, use each child asn1 object's DER bytes as value
    // turn on 6th bit (0x20 = 32) to indicate asn1 is constructed
    // from other asn1 objects
    if (obj.constructed) {
      b1 |= 0x20
    }
    else {
      // type is a bit string, add unused bits of 0x00
      value.putByte(0x00)
    }

    // add all of the child DER bytes together
    for (let i = 0; i < obj.value.length; ++i) {
      if (obj.value[i] !== undefined) {
        const derBytes = asn1.toDer(obj.value[i])
        value.putBytes(derBytes.bytes())
      }
    }
  }
  else {
    // use asn1.value directly
    if (obj.type === asn1.Type.BMPSTRING) {
      for (let i = 0; i < obj.value.length; ++i) {
        value.putInt16(obj.value.charCodeAt(i))
      }
    }
    else {
      // ensure integer is minimally-encoded
      // TODO: should all leading bytes be stripped vs just one?
      // .. ex '00 00 01' => '01'?
      if (obj.type === asn1.Type.INTEGER
        && obj.value.length > 1
        // leading 0x00 for positive integer
        && ((obj.value.charCodeAt(0) === 0
          && (obj.value.charCodeAt(1) & 0x80) === 0)
        // leading 0xFF for negative integer
        || (obj.value.charCodeAt(0) === 0xFF
          && (obj.value.charCodeAt(1) & 0x80) === 0x80))) {
        value.putBytes(obj.value.substr(1))
      }
      else {
        value.putBytes(obj.value)
      }
    }
  }

  // add tag byte
  bytes.putByte(b1)

  // use "short form" encoding
  if (value.length() <= 127) {
    // one byte describes the length
    // bit 8 = 0 and bits 7-1 = length
    bytes.putByte(value.length() & 0x7F)
  }
  else {
    // use "long form" encoding
    // 2 to 127 bytes describe the length
    // first byte: bit 8 = 1 and bits 7-1 = # of additional bytes
    // other bytes: length in base 256, big-endian
    let len = value.length()
    let lenBytes = ''
    do {
      lenBytes += String.fromCharCode(len & 0xFF)
      len = len >>> 8
    } while (len > 0)

    // set first byte to # bytes used to store the length and turn on
    // bit 8 to indicate long-form length is used
    bytes.putByte(lenBytes.length | 0x80)

    // concatenate length bytes in reverse since they were generated
    // little endian and we need big endian
    for (let i = lenBytes.length - 1; i >= 0; --i) {
      bytes.putByte(lenBytes.charCodeAt(i))
    }
  }

  // concatenate value bytes
  bytes.putBytes(value.bytes())
  return bytes
}

/**
 * Converts an OID dot-separated string to a byte buffer. The byte buffer
 * contains only the DER-encoded value, not any tag or length bytes.
 *
 * @param oid the OID dot-separated string.
 *
 * @return the byte buffer.
 */
export function oidToDer(oid: string): ByteStringBuffer {
  // split OID into individual values
  const values = oid.split('.')
  const bytes = createBuffer()

  // first byte is 40 * value1 + value2
  bytes.putByte(40 * Number.parseInt(values[0], 10) + Number.parseInt(values[1], 10))
  // other bytes are each value in base 128 with 8th bit set except for
  // the last byte for each value
  let last, valueBytes, value, b
  for (let i = 2; i < values.length; ++i) {
    // produce value bytes in reverse because we don't know how many
    // bytes it will take to store the value
    last = true
    valueBytes = []
    value = Number.parseInt(values[i], 10)
    do {
      b = value & 0x7F
      value = value >>> 7
      // if value is not last, then turn on 8th bit
      if (!last) {
        b |= 0x80
      }
      valueBytes.push(b)
      last = false
    } while (value > 0)

    // add value bytes in reverse (needs to be in big endian)
    for (let n = valueBytes.length - 1; n >= 0; --n) {
      bytes.putByte(valueBytes[n])
    }
  }

  return bytes
}

/**
 * Converts a DER-encoded byte buffer to an OID dot-separated string. The
 * byte buffer should contain only the DER-encoded value, not any tag or
 * length bytes.
 *
 * @param bytes the byte buffer.
 *
 * @return the OID dot-separated string.
 */
export function derToOid(bytes: any): string {
  let oid

  // wrap in buffer if needed
  if (typeof bytes === 'string') {
    bytes = createBuffer(bytes)
  }

  // first byte is 40 * value1 + value2
  let b = bytes.getByte()
  oid = `${Math.floor(b / 40)}.${b % 40}`

  // other bytes are each value in base 128 with 8th bit set except for
  // the last byte for each value
  let value = 0
  while (bytes.length() > 0) {
    b = bytes.getByte()
    value = value << 7
    // not the last byte for the value
    if (b & 0x80) {
      value += b & 0x7F
    }
    else {
      // last byte
      oid += `.${value + b}`
      value = 0
    }
  }

  return oid
}

/**
 * Converts a UTCTime value to a date.
 *
 * Note: GeneralizedTime has 4 digits for the year and is used for X.509
 * dates past 2049. Parsing that structure hasn't been implemented yet.
 *
 * @param utc the UTCTime value to convert.
 *
 * @return the date.
 */
export function utcTimeToDate(utc: string): Date {
  /* The following formats can be used:
    YYMMDDhhmmZ
    YYMMDDhhmm+hh'mm'
    YYMMDDhhmm-hh'mm'
    YYMMDDhhmmssZ
    YYMMDDhhmmss+hh'mm'
    YYMMDDhhmmss-hh'mm'
    Where:
    YY is the least significant two digits of the year
    MM is the month (01 to 12)
    DD is the day (01 to 31)
    hh is the hour (00 to 23)
    mm are the minutes (00 to 59)
    ss are the seconds (00 to 59)
    Z indicates that local time is GMT, + indicates that local time is
    later than GMT, and - indicates that local time is earlier than GMT
    hh' is the absolute value of the offset from GMT in hours
    mm' is the absolute value of the offset from GMT in minutes */
  const date = new Date()

  // if YY >= 50 use 19xx, if YY < 50 use 20xx
  let year = Number.parseInt(utc.substr(0, 2), 10)
  year = (year >= 50) ? 1900 + year : 2000 + year
  const MM = Number.parseInt(utc.substr(2, 2), 10) - 1 // use 0-11 for month
  const DD = Number.parseInt(utc.substr(4, 2), 10)
  const hh = Number.parseInt(utc.substr(6, 2), 10)
  const mm = Number.parseInt(utc.substr(8, 2), 10)
  let ss = 0
  let end = 0

  // not just YYMMDDhhmmZ
  if (utc.length > 11) {
    // get character after minutes
    var c = utc.charAt(10)
    end = 10

    // see if seconds are present
    if (c !== '+' && c !== '-') {
      // get seconds
      ss = Number.parseInt(utc.substr(10, 2), 10)
      end += 2
    }
  }

  // update date
  date.setUTCFullYear(year, MM, DD)
  date.setUTCHours(hh, mm, ss, 0)

  if (end) {
    // get +/- after end of time
    c = utc.charAt(end)
    if (c === '+' || c === '-') {
      // get hours+minutes offset
      const hhoffset = Number.parseInt(utc.substr(end + 1, 2), 10)
      const mmoffset = Number.parseInt(utc.substr(end + 4, 2), 10)

      // calculate offset in milliseconds
      let offset = hhoffset * 60 + mmoffset
      offset *= 60000

      // apply offset
      if (c === '+') {
        date.setTime(+date - offset)
      }
      else {
        date.setTime(+date + offset)
      }
    }
  }

  return date
}

/**
 * Converts a GeneralizedTime value to a date.
 *
 * @param gentime the GeneralizedTime value to convert.
 *
 * @return the date.
 */
export function generalizedTimeToDate(gentime: string): Date {
  /* The following formats can be used:
    YYYYMMDDHHMMSS
    YYYYMMDDHHMMSS.fff
    YYYYMMDDHHMMSSZ
    YYYYMMDDHHMMSS.fffZ
    YYYYMMDDHHMMSS+hh'mm'
    YYYYMMDDHHMMSS.fff+hh'mm'
    YYYYMMDDHHMMSS-hh'mm'
    YYYYMMDDHHMMSS.fff-hh'mm'
    Where:
    YYYY is the year
    MM is the month (01 to 12)
    DD is the day (01 to 31)
    hh is the hour (00 to 23)
    mm are the minutes (00 to 59)
    ss are the seconds (00 to 59)
    .fff is the second fraction, accurate to three decimal places
    Z indicates that local time is GMT, + indicates that local time is
    later than GMT, and - indicates that local time is earlier than GMT
    hh' is the absolute value of the offset from GMT in hours
    mm' is the absolute value of the offset from GMT in minutes */
  const date = new Date()

  const YYYY = Number.parseInt(gentime.substr(0, 4), 10)
  const MM = Number.parseInt(gentime.substr(4, 2), 10) - 1 // use 0-11 for month
  const DD = Number.parseInt(gentime.substr(6, 2), 10)
  const hh = Number.parseInt(gentime.substr(8, 2), 10)
  const mm = Number.parseInt(gentime.substr(10, 2), 10)
  const ss = Number.parseInt(gentime.substr(12, 2), 10)
  let fff = 0
  let offset = 0
  let isUTC = false

  if (gentime.charAt(gentime.length - 1) === 'Z') {
    isUTC = true
  }

  const end = gentime.length - 5; const c = gentime.charAt(end)
  if (c === '+' || c === '-') {
    // get hours+minutes offset
    const hhoffset = Number.parseInt(gentime.substr(end + 1, 2), 10)
    const mmoffset = Number.parseInt(gentime.substr(end + 4, 2), 10)

    // calculate offset in milliseconds
    offset = hhoffset * 60 + mmoffset
    offset *= 60000

    // apply offset
    if (c === '+') {
      offset *= -1
    }

    isUTC = true
  }

  // check for second fraction
  if (gentime.charAt(14) === '.') {
    fff = Number.parseFloat(gentime.substr(14)) * 1000
  }

  if (isUTC) {
    date.setUTCFullYear(YYYY, MM, DD)
    date.setUTCHours(hh, mm, ss, fff)

    // apply offset
    date.setTime(+date + offset)
  }
  else {
    date.setFullYear(YYYY, MM, DD)
    date.setHours(hh, mm, ss, fff)
  }

  return date
}

/**
 * Converts a date to a UTCTime value.
 *
 * Note: GeneralizedTime has 4 digits for the year and is used for X.509
 * dates past 2049. Converting to a GeneralizedTime hasn't been
 * implemented yet.
 *
 * @param date the date to convert.
 *
 * @return the UTCTime value.
 */
export function dateToUtcTime(date: Date): string {
  // TODO: validate; currently assumes proper format
  if (typeof date === 'string')
    return date

  let rval = ''

  // create format YYMMDDhhmmssZ
  const format = []
  format.push((`${date.getUTCFullYear()}`).substr(2))
  format.push(`${date.getUTCMonth() + 1}`)
  format.push(`${date.getUTCDate()}`)
  format.push(`${date.getUTCHours()}`)
  format.push(`${date.getUTCMinutes()}`)
  format.push(`${date.getUTCSeconds()}`)

  // ensure 2 digits are used for each format entry
  for (let i = 0; i < format.length; ++i) {
    if (format[i].length < 2) {
      rval += '0'
    }
    rval += format[i]
  }
  rval += 'Z'

  return rval
}

/**
 * Converts a date to a GeneralizedTime value.
 *
 * @param date the date to convert.
 *
 * @return the GeneralizedTime value as a string.
 */
export function dateToGeneralizedTime(date: Date): string {
  // TODO: validate; currently assumes proper format
  if (typeof date === 'string') {
    return date
  }

  let rval = ''

  // create format YYYYMMDDHHMMSSZ
  const format = []
  format.push(`${date.getUTCFullYear()}`)
  format.push(`${date.getUTCMonth() + 1}`)
  format.push(`${date.getUTCDate()}`)
  format.push(`${date.getUTCHours()}`)
  format.push(`${date.getUTCMinutes()}`)
  format.push(`${date.getUTCSeconds()}`)

  // ensure 2 digits are used for each format entry
  for (let i = 0; i < format.length; ++i) {
    if (format[i].length < 2) {
      rval += '0'
    }
    rval += format[i]
  }
  rval += 'Z'

  return rval
}

/**
 * Converts a javascript integer to a DER-encoded byte buffer to be used
 * as the value for an INTEGER type.
 *
 * @param x the integer.
 *
 * @return the byte buffer.
 */
export function integerToDer(x: number): ByteStringBuffer {
  const rval = createBuffer()
  if (x >= -0x80 && x < 0x80)
    return rval.putByte(x)

  if (x >= -0x8000 && x < 0x8000) {
    rval.putByte((x >> 8) & 0xFF)
    return rval.putByte(x & 0xFF)
  }

  if (x >= -0x800000 && x < 0x800000) {
    rval.putByte((x >> 16) & 0xFF)
    rval.putByte((x >> 8) & 0xFF)
    return rval.putByte(x & 0xFF)
  }

  if (x >= -0x80000000 && x < 0x80000000) {
    rval.putByte((x >> 24) & 0xFF)
    rval.putByte((x >> 16) & 0xFF)
    rval.putByte((x >> 8) & 0xFF)
    return rval.putByte(x & 0xFF)
  }

  const error = new Error('Integer too large; max is 32-bits.') as ExtendedError
  error.integer = x
  throw error
}

/**
 * Converts a DER-encoded byte buffer to a javascript integer. This is
 * typically used to decode the value of an INTEGER type.
 *
 * @param bytes the byte buffer.
 *
 * @return the integer.
 */
export function derToInteger(bytes: any): number {
  // wrap in buffer if needed
  if (typeof bytes === 'string') {
    bytes = createBuffer(bytes)
  }

  const n = bytes.length() * 8
  if (n > 32) {
    throw new Error('Integer too large; max is 32-bits.')
  }
  return bytes.getSignedInt(n)
}

/**
 * Validates that the given ASN.1 object is at least a super set of the
 * given ASN.1 structure. Only tag classes and types are checked. An
 * optional map may also be provided to capture ASN.1 values while the
 * structure is checked.
 *
 * To capture an ASN.1 value, set an object in the validator's 'capture'
 * parameter to the key to use in the capture map. To capture the full
 * ASN.1 object, specify 'captureAsn1'. To capture BIT STRING bytes, including
 * the leading unused bits counter byte, specify 'captureBitStringContents'.
 * To capture BIT STRING bytes, without the leading unused bits counter byte,
 * specify 'captureBitStringValue'.
 *
 * Objects in the validator may set a field 'optional' to true to indicate
 * that it isn't necessary to pass validation.
 *
 * @param obj the ASN.1 object to validate.
 * @param v the ASN.1 structure validator.
 * @param capture an optional map to capture values in.
 * @param errors an optional array for storing validation errors.
 *
 * @return true on success, false on failure.
 */
export function validate(obj: any, v: any, capture: any, errors: any): boolean {
  let rval = false

  // ensure tag class and type are the same if specified
  if ((obj.tagClass === v.tagClass || typeof (v.tagClass) === 'undefined')
    && (obj.type === v.type || typeof (v.type) === 'undefined')) {
    // ensure constructed flag is the same if specified
    if (obj.constructed === v.constructed
      || typeof (v.constructed) === 'undefined') {
      rval = true

      // handle sub values
      if (v.value && Array.isArray(v.value)) {
        let j = 0
        for (let i = 0; rval && i < v.value.length; ++i) {
          rval = v.value[i].optional || false
          if (obj.value[j]) {
            rval = asn1.validate(obj.value[j], v.value[i], capture, errors)
            if (rval) {
              ++j
            }
            else if (v.value[i].optional) {
              rval = true
            }
          }
          if (!rval && errors) {
            errors.push(
              `[${v.name}] `
              + `Tag class "${v.tagClass}", type "${v.type}" expected value length "${v.value.length}", got "${obj.value.length}"`,
            )
          }
        }
      }

      if (rval && capture) {
        if (v.capture) {
          capture[v.capture] = obj.value
        }
        if (v.captureAsn1) {
          capture[v.captureAsn1] = obj
        }
        if (v.captureBitStringContents && 'bitStringContents' in obj) {
          capture[v.captureBitStringContents] = obj.bitStringContents
        }
        if (v.captureBitStringValue && 'bitStringContents' in obj) {
          let value
          if (obj.bitStringContents.length < 2) {
            capture[v.captureBitStringValue] = ''
          }
          else {
            // FIXME: support unused bits with data shifting
            const unused = obj.bitStringContents.charCodeAt(0)
            if (unused !== 0) {
              throw new Error(
                'captureBitStringValue only supported for zero unused bits',
              )
            }
            capture[v.captureBitStringValue] = obj.bitStringContents.slice(1)
          }
        }
      }
    }
    else if (errors) {
      errors.push(
        `[${v.name}] `
        + `Expected constructed "${v.constructed}", got "${obj.constructed}"`,
      )
    }
  }
  else if (errors) {
    if (obj.tagClass !== v.tagClass) {
      errors.push(
        `[${v.name}] `
        + `Expected tag class "${v.tagClass}", got "${obj.tagClass}"`,
      )
    }
    if (obj.type !== v.type) {
      errors.push(
        `[${v.name}] `
        + `Expected type "${v.type}", got "${obj.type}"`,
      )
    }
  }
  return rval
}

// regex for testing for non-latin characters
const _nonLatinRegex = /[^u0-\\f]/

/**
 * Pretty prints an ASN.1 object to a string.
 *
 * @param obj the object to write out.
 * @param level the level in the tree.
 * @param indentation the indentation to use.
 *
 * @return the string.
 */
export function prettyPrint(obj: any, level?: number, indentation?: number): string {
  let rval = ''

  // set default level and indentation
  level = level || 0
  indentation = indentation || 2

  // start new line for deep levels
  if (level > 0) {
    rval += '\n'
  }

  // create indent
  let indent = ''
  for (var i = 0; i < level * indentation; ++i) {
    indent += ' '
  }

  // print class:type
  rval += `${indent}Tag: `
  switch (obj.tagClass) {
    case asn1.Class.UNIVERSAL:
      rval += 'Universal:'
      break
    case asn1.Class.APPLICATION:
      rval += 'Application:'
      break
    case asn1.Class.CONTEXT_SPECIFIC:
      rval += 'Context-Specific:'
      break
    case asn1.Class.PRIVATE:
      rval += 'Private:'
      break
  }

  if (obj.tagClass === asn1.Class.UNIVERSAL) {
    rval += obj.type

    // known types
    switch (obj.type) {
      case asn1.Type.NONE:
        rval += ' (None)'
        break
      case asn1.Type.BOOLEAN:
        rval += ' (Boolean)'
        break
      case asn1.Type.INTEGER:
        rval += ' (Integer)'
        break
      case asn1.Type.BITSTRING:
        rval += ' (Bit string)'
        break
      case asn1.Type.OCTETSTRING:
        rval += ' (Octet string)'
        break
      case asn1.Type.NULL:
        rval += ' (Null)'
        break
      case asn1.Type.OID:
        rval += ' (Object Identifier)'
        break
      case asn1.Type.ODESC:
        rval += ' (Object Descriptor)'
        break
      case asn1.Type.EXTERNAL:
        rval += ' (External or Instance of)'
        break
      case asn1.Type.REAL:
        rval += ' (Real)'
        break
      case asn1.Type.ENUMERATED:
        rval += ' (Enumerated)'
        break
      case asn1.Type.EMBEDDED:
        rval += ' (Embedded PDV)'
        break
      case asn1.Type.UTF8:
        rval += ' (UTF8)'
        break
      case asn1.Type.ROID:
        rval += ' (Relative Object Identifier)'
        break
      case asn1.Type.SEQUENCE:
        rval += ' (Sequence)'
        break
      case asn1.Type.SET:
        rval += ' (Set)'
        break
      case asn1.Type.PRINTABLESTRING:
        rval += ' (Printable String)'
        break
      case asn1.Type.IA5STRING:
        rval += ' (IA5String (ASCII))'
        break
      case asn1.Type.UTCTIME:
        rval += ' (UTC time)'
        break
      case asn1.Type.GENERALIZEDTIME:
        rval += ' (Generalized time)'
        break
      case asn1.Type.BMPSTRING:
        rval += ' (BMP String)'
        break
    }
  }
  else {
    rval += obj.type
  }

  rval += '\n'
  rval += `${indent}Constructed: ${obj.constructed}\n`

  if (obj.composed) {
    let subvalues = 0
    let sub = ''
    for (var i = 0; i < obj.value.length; ++i) {
      if (obj.value[i] !== undefined) {
        subvalues += 1
        sub += asn1.prettyPrint(obj.value[i], level + 1, indentation)
        if ((i + 1) < obj.value.length) {
          sub += ','
        }
      }
    }
    rval += `${indent}Sub values: ${subvalues}${sub}`
  }
  else {
    rval += `${indent}Value: `
    if (obj.type === asn1.Type.OID) {
      const oid = asn1.derToOid(obj.value)
      rval += oid
      if (oid in oids) {
        rval += ` (${oids[oid]}) `
      }
    }
    if (obj.type === asn1.Type.INTEGER) {
      try {
        rval += asn1.derToInteger(obj.value)
      }
      catch (ex) {
        rval += `0x${bytesToHex(obj.value)}`
      }
    }
    else if (obj.type === asn1.Type.BITSTRING) {
      // TODO: shift bits as needed to display without padding
      if (obj.value.length > 1) {
        // remove unused bits field
        rval += `0x${bytesToHex(obj.value.slice(1))}`
      }
      else {
        rval += '(none)'
      }
      // show unused bit count
      if (obj.value.length > 0) {
        const unused = obj.value.charCodeAt(0)
        if (unused == 1) {
          rval += ' (1 unused bit shown)'
        }
        else if (unused > 1) {
          rval += ` (${unused} unused bits shown)`
        }
      }
    }
    else if (obj.type === asn1.Type.OCTETSTRING) {
      if (!_nonLatinRegex.test(obj.value)) {
        rval += `(${obj.value}) `
      }
      rval += `0x${bytesToHex(obj.value)}`
    }
    else if (obj.type === asn1.Type.UTF8) {
      try {
        rval += decodeUtf8(obj.value)
      }
      catch (e: unknown) {
        if (e instanceof Error && e.message === 'URI malformed') {
          rval += `0x${bytesToHex(obj.value)} (malformed UTF8)`
        }
        else {
          throw e
        }
      }
    }
    else if (obj.type === asn1.Type.PRINTABLESTRING
      || obj.type === asn1.Type.IA5STRING) {
      rval += obj.value
    }
    else if (_nonLatinRegex.test(obj.value)) {
      rval += `0x${bytesToHex(obj.value)}`
    }
    else if (obj.value.length === 0) {
      rval += '[null]'
    }
    else {
      rval += obj.value
    }
  }

  return rval
}

export interface Asn1 {
  Class: typeof Class
  Type: typeof Type
  create: typeof createAsn1Object
  copy: typeof copy
  equals: typeof equals
  getBerValueLength: typeof getBerValueLength
  fromDer: typeof fromDer
  oidToDer: typeof oidToDer
  derToOid: typeof derToOid
  utcTimeToDate: typeof utcTimeToDate
  generalizedTimeToDate: typeof generalizedTimeToDate
  dateToUtcTime: typeof dateToUtcTime
  dateToGeneralizedTime: typeof dateToGeneralizedTime
  integerToDer: typeof integerToDer
  derToInteger: typeof derToInteger
  validate: typeof validate
  prettyPrint: typeof prettyPrint
  toDer: typeof toDer
}

export const asn1: Asn1 = {
  Class,
  Type,
  create: createAsn1Object,
  copy,
  equals,
  getBerValueLength,
  fromDer,
  oidToDer,
  derToOid,
  utcTimeToDate,
  generalizedTimeToDate,
  dateToUtcTime,
  dateToGeneralizedTime,
  integerToDer,
  derToInteger,
  validate,
  prettyPrint,
  toDer,
} as const

export default asn1
