/**
 * TypeScript implementation of X.509 and related components (such as
 * Certification Signing Requests) of a Public Key Infrastructure.
 *
 * @author Dave Longley
 * @author Chris Breuer
 *
 * The ASN.1 representation of an X.509v3 certificate is as follows
 * (see RFC 2459):
 *
 * Certificate ::= SEQUENCE {
 *   tbsCertificate       TBSCertificate,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING
 * }
 *
 * TBSCertificate ::= SEQUENCE {
 *   version         [0]  EXPLICIT Version DEFAULT v1,
 *   serialNumber         CertificateSerialNumber,
 *   signature            AlgorithmIdentifier,
 *   issuer               Name,
 *   validity             Validity,
 *   subject              Name,
 *   subjectPublicKeyInfo SubjectPublicKeyInfo,
 *   issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                        -- If present, version shall be v2 or v3
 *   subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                        -- If present, version shall be v2 or v3
 *   extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                        -- If present, version shall be v3
 * }
 *
 * Version ::= INTEGER  { v1(0), v2(1), v3(2) }
 *
 * CertificateSerialNumber ::= INTEGER
 *
 * Name ::= CHOICE {
 *   // only one possible choice for now
 *   RDNSequence
 * }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE {
 *   type     AttributeType,
 *   value    AttributeValue
 * }
 * AttributeType ::= OBJECT IDENTIFIER
 * AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * Validity ::= SEQUENCE {
 *   notBefore      Time,
 *   notAfter       Time
 * }
 *
 * Time ::= CHOICE {
 *   utcTime        UTCTime,
 *   generalTime    GeneralizedTime
 * }
 *
 * UniqueIdentifier ::= BIT STRING
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm            AlgorithmIdentifier,
 *   subjectPublicKey     BIT STRING
 * }
 *
 * Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension ::= SEQUENCE {
 *   extnID      OBJECT IDENTIFIER,
 *   critical    BOOLEAN DEFAULT FALSE,
 *   extnValue   OCTET STRING
 * }
 *
 * The only key algorithm currently supported for PKI is RSA.
 *
 * RSASSA-PSS signatures are described in RFC 3447 and RFC 4055.
 *
 * PKCS#10 v1.7 describes certificate signing requests:
 *
 * CertificationRequestInfo:
 *
 * CertificationRequestInfo ::= SEQUENCE {
 *   version       INTEGER { v1(0) } (v1,...),
 *   subject       Name,
 *   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes    [0] Attributes{{ CRIAttributes }}
 * }
 *
 * Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 * CRIAttributes  ATTRIBUTE  ::= {
 *   ... -- add any locally defined attributes here -- }
 *
 * Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *   type   ATTRIBUTE.&id({IOSet}),
 *   values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 * }
 *
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo CertificationRequestInfo,
 *   signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *   signature          BIT STRING
 * }
 */

import type { Asn1Object } from './encoding/asn1'
import { asn1 } from './encoding/asn1'
import { md } from './md'
import { oids } from './oids'
import { pki } from './pki'
import { mgf as mgfImport } from './mgf'
import util, { hexToBytes } from './utils'
import { pem } from './encoding/pem'
import { publicKeyToAsn1, publicKeyFromAsn1 } from './algorithms/asymmetric/rsa'
import { pss } from './pss'

// Constants
const DATE_1950 = new Date('1950-01-01T00:00:00Z')
const DATE_2050 = new Date('2050-01-01T00:00:00Z')

// Interfaces
interface CaptureObject {
  [key: string]: any
}

interface SignatureParameters {
  hash?: {
    algorithmOid: string
  }
  mgf?: {
    algorithmOid: string
    hash: {
      algorithmOid: string
    }
  }
  saltLength?: number
  trailerField?: number
}

interface CustomError {
  message: string
  errors?: any[]
  signatureOid?: string
  oid?: string
  name?: string
  headerType?: string
  algorithm?: string
  attribute?: any
  extension?: any
  notBefore?: Date
  notAfter?: Date
  now?: Date
  expectedIssuer?: any[]
  actualIssuer?: any[]
  details?: string
}

export interface RDNAttribute {
  type: string
  value: any
  valueTagClass: number
  name?: string
  shortName?: string
  extensions?: any[]
}

export interface Certificate {
  version: number
  serialNumber: string
  signatureOid: string | null
  signature: any
  signatureParameters?: SignatureParameters
  siginfo: {
    algorithmOid: string | null
    parameters?: any
  }
  validity: {
    notBefore: Date
    notAfter: Date
  }
  issuer: {
    getField: (sn: string) => RDNAttribute | null
    addField: (attr: RDNAttribute) => void
    attributes: RDNAttribute[]
    hash: string | null
    uniqueId?: string
  }
  subject: {
    getField: (sn: string) => RDNAttribute | null
    addField: (attr: RDNAttribute) => void
    attributes: RDNAttribute[]
    hash: string | null
    uniqueId?: string
  }
  extensions: CertificateExtension[]
  publicKey: any
  md: IMessageDigest | null
  tbsCertificate?: any
  issued: (child: Certificate) => boolean
  isIssuer: (parent: Certificate) => boolean
  generateSubjectKeyIdentifier: () => any
  verifySubjectKeyIdentifier: () => boolean
  verify?: (cert: Certificate) => boolean
}

export interface CertificateExtension {
  id: string
  critical: boolean
  value: any
  name?: string
  [key: string]: any
}

export interface CertificationRequest {
  version: number
  signatureOid: string | null
  signatureParameters?: SignatureParameters
  signature: any
  siginfo: {
    algorithmOid: string | null
    parameters?: any
  }
  subject: {
    getField: (sn: string) => RDNAttribute | null
    addField: (attr: RDNAttribute) => void
    attributes: RDNAttribute[]
    hash: string | null
  }
  publicKey: any
  attributes: RDNAttribute[]
  getAttribute: (sn: string) => RDNAttribute | null
  addAttribute: (attr: RDNAttribute) => void
  md: IMessageDigest | null
  certificationRequestInfo?: any
  setSubject: (attrs: RDNAttribute[]) => void
  setAttributes: (attrs: RDNAttribute[]) => void
  sign: (key: any, md?: IMessageDigest) => void
  verify: () => boolean
}

export interface CAStore {
  certs: { [key: string]: Certificate | Certificate[] }
  getIssuer: (cert: Certificate) => Certificate | null
  addCertificate: (cert: Certificate | string) => void
  hasCertificate: (cert: Certificate | string) => boolean
  listAllCertificates: () => Certificate[]
  removeCertificate: (cert: Certificate | string) => Certificate | null
}

// short name OID mappings
const _shortNames = {
  CN: oids.commonName,
  commonName: 'CN',
  C: oids.countryName,
  countryName: 'C',
  L: oids.localityName,
  localityName: 'L',
  ST: oids.stateOrProvinceName,
  stateOrProvinceName: 'ST',
  O: oids.organizationName,
  organizationName: 'O',
  OU: oids.organizationalUnitName,
  organizationalUnitName: 'OU',
  E: oids.emailAddress,
  emailAddress: 'E',
} as const

// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
const publicKeyValidator = pki.rsa.publicKeyValidator

// validator for an X.509v3 certificate
export const x509CertificateValidator: Asn1Object = {
  name: 'Certificate',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'Certificate.TBSCertificate',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    captureAsn1: 'tbsCertificate',
    value: [{
      name: 'Certificate.TBSCertificate.version',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 0,
      constructed: true,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.version.integer',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.INTEGER,
        constructed: false,
        capture: 'certVersion',
      }],
    }, {
      name: 'Certificate.TBSCertificate.serialNumber',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'certSerialNumber',
    }, {
      name: 'Certificate.TBSCertificate.signature',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        name: 'Certificate.TBSCertificate.signature.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'certinfoSignatureOid',
      }, {
        name: 'Certificate.TBSCertificate.signature.parameters',
        tagClass: asn1.Class.UNIVERSAL,
        optional: true,
        captureAsn1: 'certinfoSignatureParams',
      }],
    }, {
      name: 'Certificate.TBSCertificate.issuer',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'certIssuer',
    }, {
      name: 'Certificate.TBSCertificate.validity',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      // Note: UTC and generalized times may both appear so the capture
      // names are based on their detected order, the names used below
      // are only for the common case, which validity time really means
      // "notBefore" and which means "notAfter" will be determined by order
      value: [{
        // notBefore (Time) (UTC time case)
        name: 'Certificate.TBSCertificate.validity.notBefore (utc)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.UTCTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity1UTCTime',
      }, {
        // notBefore (Time) (generalized time case)
        name: 'Certificate.TBSCertificate.validity.notBefore (generalized)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.GENERALIZEDTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity2GeneralizedTime',
      }, {
        // notAfter (Time) (only UTC time is supported)
        name: 'Certificate.TBSCertificate.validity.notAfter (utc)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.UTCTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity3UTCTime',
      }, {
        // notAfter (Time) (only UTC time is supported)
        name: 'Certificate.TBSCertificate.validity.notAfter (generalized)',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.GENERALIZEDTIME,
        constructed: false,
        optional: true,
        capture: 'certValidity4GeneralizedTime',
      }],
    }, {
      // Name (subject) (RDNSequence)
      name: 'Certificate.TBSCertificate.subject',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'certSubject',
    },
    // SubjectPublicKeyInfo
    publicKeyValidator, {
      // issuerUniqueID (optional)
      name: 'Certificate.TBSCertificate.issuerUniqueID',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 1,
      constructed: true,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.issuerUniqueID.id',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.BITSTRING,
        constructed: false,
        // TODO: support arbitrary bit length ids
        captureBitStringValue: 'certIssuerUniqueId',
      }],
    }, {
      // subjectUniqueID (optional)
      name: 'Certificate.TBSCertificate.subjectUniqueID',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 2,
      constructed: true,
      optional: true,
      value: [{
        name: 'Certificate.TBSCertificate.subjectUniqueID.id',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.BITSTRING,
        constructed: false,
        // TODO: support arbitrary bit length ids
        captureBitStringValue: 'certSubjectUniqueId',
      }],
    }, {
      // Extensions (optional)
      name: 'Certificate.TBSCertificate.extensions',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: 3,
      constructed: true,
      captureAsn1: 'certExtensions',
      optional: true,
    }],
  }, {
    // AlgorithmIdentifier (signature algorithm)
    name: 'Certificate.signatureAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      // algorithm
      name: 'Certificate.signatureAlgorithm.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'certSignatureOid',
    }, {
      name: 'Certificate.TBSCertificate.signature.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      optional: true,
      captureAsn1: 'certSignatureParams',
    }],
  }, {
    // SignatureValue
    name: 'Certificate.signatureValue',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.BITSTRING,
    constructed: false,
    captureBitStringValue: 'certSignature',
  }],
}

export const rsassaPssParameterValidator: Asn1Object = {
  name: 'rsapss',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'rsapss.hashAlgorithm',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0,
    constructed: true,
    value: [{
      name: 'rsapss.hashAlgorithm.AlgorithmIdentifier',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Class.SEQUENCE,
      constructed: true,
      optional: true,
      value: [{
        name: 'rsapss.hashAlgorithm.AlgorithmIdentifier.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'hashOid',
        /* parameter block omitted, for SHA1 NULL anyhow. */
      }],
    }],
  }, {
    name: 'rsapss.maskGenAlgorithm',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 1,
    constructed: true,
    value: [{
      name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Class.SEQUENCE,
      constructed: true,
      optional: true,
      value: [{
        name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'maskGenOid',
      }, {
        name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SEQUENCE,
        constructed: true,
        value: [{
          name: 'rsapss.maskGenAlgorithm.AlgorithmIdentifier.params.algorithm',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.OID,
          constructed: false,
          capture: 'maskGenHashOid',
          /* parameter block omitted, for SHA1 NULL anyhow. */
        }],
      }],
    }],
  }, {
    name: 'rsapss.saltLength',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 2,
    optional: true,
    value: [{
      name: 'rsapss.saltLength.saltLength',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'saltLength',
    }],
  }, {
    name: 'rsapss.trailerField',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 3,
    optional: true,
    value: [{
      name: 'rsapss.trailer.trailer',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'trailer',
    }],
  }],
}

// validator for a CertificationRequestInfo structure
export const certificationRequestInfoValidator: Asn1Object = {
  name: 'CertificationRequestInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'certificationRequestInfo',
  value: [{
    name: 'CertificationRequestInfo.integer',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'certificationRequestInfoVersion',
  }, {
    // Name (subject) (RDNSequence)
    name: 'CertificationRequestInfo.subject',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    captureAsn1: 'certificationRequestInfoSubject',
  },
  // SubjectPublicKeyInfo
  publicKeyValidator, {
    name: 'CertificationRequestInfo.attributes',
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0,
    constructed: true,
    optional: true,
    capture: 'certificationRequestInfoAttributes',
    value: [{
      name: 'CertificationRequestInfo.attributes',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        name: 'CertificationRequestInfo.attributes.type',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
      }, {
        name: 'CertificationRequestInfo.attributes.value',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.SET,
        constructed: true,
      }],
    }],
  }],
}

// validator for a CertificationRequest structure
export const certificationRequestValidator: Asn1Object = {
  name: 'CertificationRequest',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'csr',
  value: [
    certificationRequestInfoValidator,
    {
      // AlgorithmIdentifier (signature algorithm)
      name: 'CertificationRequest.signatureAlgorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [{
        // algorithm
        name: 'CertificationRequest.signatureAlgorithm.algorithm',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        capture: 'csrSignatureOid',
      }, {
        name: 'CertificationRequest.signatureAlgorithm.parameters',
        tagClass: asn1.Class.UNIVERSAL,
        optional: true,
        captureAsn1: 'csrSignatureParams',
      }],
    },
    {
      // signature
      name: 'CertificationRequest.signature',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.BITSTRING,
      constructed: false,
      captureBitStringValue: 'csrSignature',
    },
  ],
}

/**
 * Converts an RDNSequence of ASN.1 DER-encoded RelativeDistinguishedName
 * sets into an array with objects that have type and value properties.
 *
 * @param rdn the RDNSequence to convert.
 * @param md a message digest to append type and value to if provided.
 */
export function RDNAttributesAsArray(rdn: any, md?: IMessageDigest): RDNAttribute[] {
  const rval: RDNAttribute[] = []

  // each value can be a string or array of strings
  for (let i = 0; i < rdn.value.length; ++i) {
    const attr = rdn.value[i]

    // handle values as an array
    for (let vi = 0; vi < attr.value.length; ++vi) {
      // get value
      let value = attr.value[vi]

      // handle value as an array
      if (Array.isArray(value)) {
        for (let n = 0; n < value.length; ++n) {
          const obj: RDNAttribute = {
            type: attr.type,
            value: value[n],
            valueTagClass: attr.valueTagClass || asn1.Class.UNIVERSAL,
            name: undefined,
            shortName: undefined,
          }
          if (md) {
            md.update(obj.type)
            md.update(obj.value)
          }
          rval.push(obj)
        }
      }
      else {
        const obj: RDNAttribute = {
          type: attr.type,
          value,
          valueTagClass: attr.valueTagClass || asn1.Class.UNIVERSAL,
          name: undefined,
          shortName: undefined,
        }
        if (md) {
          md.update(obj.type)
          md.update(obj.value)
        }
        rval.push(obj)
      }
    }
  }

  return rval
}

/**
 * Converts ASN.1 CRIAttributes into an array with objects that have type and
 * value properties.
 *
 * @param attributes the CRIAttributes to convert.
 */
export function CRIAttributesAsArray(attributes: any): RDNAttribute[] {
  const rval: RDNAttribute[] = []

  for (let i = 0; i < attributes.length; ++i) {
    const attr = attributes[i]
    let value = attr.value

    // handle values as an array
    if (Array.isArray(value)) {
      for (let n = 0; n < value.length; ++n) {
        const obj: RDNAttribute = {
          type: attr.type,
          value: value[n],
          valueTagClass: attr.valueTagClass || asn1.Class.UNIVERSAL,
          name: undefined,
          shortName: undefined,
        }
        rval.push(obj)
      }
    }
    else {
      const obj: RDNAttribute = {
        type: attr.type,
        value,
        valueTagClass: attr.valueTagClass || asn1.Class.UNIVERSAL,
        name: undefined,
        shortName: undefined,
      }
      rval.push(obj)
    }
  }

  return rval
}

/**
 * Gets an issuer or subject attribute from its name, type, or short name.
 *
 * @param obj the issuer or subject object.
 * @param options a short name string or an object with:
 * @param options.shortName the short name for the attribute.
 * @param options.name the name for the attribute.
 * @param options.type the type for the attribute.
 *
 * @return the attribute.
 */
export function getAttribute(obj: any, options: any): RDNAttribute | null {
  if (typeof options === 'string') {
    options = { shortName: options }
  }

  let rval = null
  const attr = obj.attributes
  for (let i = 0; rval === null && i < attr.length; ++i) {
    if (options.type && options.type === attr[i].type) {
      rval = attr[i]
    }
    else if (options.shortName && options.shortName === attr[i].shortName) {
      rval = attr[i]
    }
  }
  return rval
}

/**
 * Converts signature parameters from ASN.1 structure.
 *
 * Currently only RSASSA-PSS supported.  The PKCS#1 v1.5 signature scheme had no parameters.
 *
 * RSASSA-PSS-params  ::=  SEQUENCE  {
 *   hashAlgorithm      [0] HashAlgorithm DEFAULT
 *                             sha1Identifier,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
 *                             mgf1SHA1Identifier,
 *   saltLength         [2] INTEGER DEFAULT 20,
 *   trailerField       [3] INTEGER DEFAULT 1
 * }
 *
 * HashAlgorithm  ::=  AlgorithmIdentifier
 *
 * MaskGenAlgorithm  ::=  AlgorithmIdentifier
 *
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * @param oid The OID specifying the signature algorithm
 * @param obj The ASN.1 structure holding the parameters
 * @param fillDefaults Whether to use return default values where omitted
 * @return signature parameter object
 */
export function readSignatureParameters(
  oid: string,
  obj: any,
  fillDefaults: boolean
): SignatureParameters {
  const params: SignatureParameters = {}

  if (oid !== oids['RSASSA-PSS']) {
    return params
  }

  if (fillDefaults) {
    params.hash = { algorithmOid: oids.sha1 }
    params.mgf = {
      algorithmOid: oids.mgf1,
      hash: { algorithmOid: oids.sha1 },
    }
    params.saltLength = 20
  }

  const capture: CaptureObject = {}
  const errors: any[] = []
  if (!asn1.validate(obj, rsassaPssParameterValidator, capture, errors)) {
    throw {
      message: 'Cannot read RSASSA-PSS parameter block.',
      error: 'pki.BadCertificate',
      errors
    } as CustomError
  }

  if (capture.hashOid !== undefined) {
    params.hash = { algorithmOid: asn1.derToOid(capture.hashOid) }
  }

  if (capture.maskGenOid !== undefined) {
    params.mgf = {
      algorithmOid: asn1.derToOid(capture.maskGenOid),
      hash: { algorithmOid: asn1.derToOid(capture.maskGenHashOid) }
    }
  }

  if (capture.saltLength !== undefined) {
    params.saltLength = capture.saltLength.charCodeAt(0)
  }

  return params
}

interface ByteStringBuffer {
  toHex: () => string
  getBytes: () => string
}

interface IMessageDigest {
  algorithm: string
  update: (msg: string | ByteStringBuffer, encoding?: string) => IMessageDigest
  digest: () => ByteStringBuffer
  create: () => IMessageDigest
}

interface HashFunction {
  create: () => IMessageDigest
}

interface HashFunctions {
  [key: string]: HashFunction
}

interface MaskGenFunction {
  create: (md: IMessageDigest) => any
}

interface MaskGenFunctions {
  [key: string]: MaskGenFunction
}

// Add at the top of the file after imports
interface ExtendedError extends Error {
  headerType?: string
  errors?: any[]
  algorithm?: string
  attribute?: any
  extension?: any
}

interface PemMessage {
  type: string
  body: string
  procType?: any
  contentDomain?: any
  dekInfo?: any
  headers?: any[]
}

// Update verifySignature function
export function verifySignature(options: {
  certificate: Certificate
  md: IMessageDigest
  signature: any
}): boolean {
  let rval = false

  if (options.certificate.signatureOid === oids['RSASSA-PSS']) {
    const params = options.certificate.signatureParameters
    if (!params) {
      throw {
        message: 'Missing signature parameters',
        error: 'pki.BadCertificate'
      } as CustomError
    }

    const hashAlgorithm = params.mgf?.hash?.algorithmOid
    if (!hashAlgorithm || !((md as unknown as HashFunctions)[hashAlgorithm])) {
      throw {
        message: 'Unsupported MGF hash function.',
        error: 'pki.BadCertificate',
        oid: params.mgf?.hash?.algorithmOid
      } as CustomError
    }

    const mgfOid = params.mgf?.algorithmOid
    if (!mgfOid || !((mgfImport as unknown as MaskGenFunctions)[mgfOid])) {
      throw {
        message: 'Unsupported MGF function.',
        error: 'pki.BadCertificate',
        oid: mgfOid
      } as CustomError
    }

    const mgf = (mgfImport as unknown as MaskGenFunctions)[mgfOid].create(
      (md as unknown as HashFunctions)[hashAlgorithm].create()
    )

    // initialize hash function
    const hashOid = params.hash?.algorithmOid
    if (!hashOid || !((md as unknown as HashFunctions)[hashOid])) {
      throw {
        message: 'Unsupported RSASSA-PSS hash function.',
        error: 'pki.BadCertificate',
        oid: hashOid
      } as CustomError
    }

    const hashFn = (md as unknown as HashFunctions)[hashOid].create()
    rval = options.certificate.publicKey.verify(
      options.md.digest().getBytes(),
      options.signature,
      { mgf, hash: hashFn, saltLength: params.saltLength || 20 }
    )
  }
  else {
    rval = options.certificate.publicKey.verify(
      options.md.digest().getBytes(),
      options.signature
    )
  }

  return rval
}

/**
 * Converts an X.509 certificate from PEM format.
 *
 * Note: If the certificate is to be verified then compute hash should
 * be set to true. This will scan the TBSCertificate part of the ASN.1
 * object while it is converted so it doesn't need to be converted back
 * to ASN.1-DER-encoding later.
 *
 * @param pem the PEM-formatted certificate.
 * @param computeHash true to compute the hash for verification.
 * @param strict true to be strict when checking ASN.1 value lengths, false to
 *          allow truncated values (default: true).
 *
 * @return the certificate.
 */
export function certificateFromPem(pemString: string, computeHash: boolean, strict: boolean): Certificate {
  const msg = pem.decode(pemString)[0]

  if (msg.type !== 'CERTIFICATE' && msg.type !== 'X509 CERTIFICATE'
      && msg.type !== 'TRUSTED CERTIFICATE') {
    const error = new Error('Could not convert certificate from PEM; PEM header type is not "CERTIFICATE".') as ExtendedError
    error.headerType = msg.type
    throw error
  }

  // convert DER to ASN.1 object
  return certificateFromAsn1(asn1.fromDer(msg.body), computeHash)
}

/**
 * Converts an X.509 certificate to PEM format.
 *
 * @param cert the certificate.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted certificate.
 */
export function certificateToPem(cert: Certificate, maxline: number): string {
  // convert to ASN.1, then DER, then PEM-encode
  const msg = {
    type: 'CERTIFICATE',
    body: asn1.toDer(certificateToAsn1(cert)).getBytes(),
  }

  return pem.encode(msg, { maxline })
}

/**
 * Converts an RSA public key from PEM format.
 *
 * @param pem the PEM-formatted public key.
 *
 * @return the public key.
 */
export function publicKeyFromPem(pemString: string): any {
  const msg = pem.decode(pemString)[0]

  if (msg.type !== 'PUBLIC KEY' && msg.type !== 'RSA PUBLIC KEY') {
    const error: CustomError = new Error('Could not convert public key from PEM; PEM header type is not "PUBLIC KEY" or "RSA PUBLIC KEY".')
    error.headerType = msg.type
    throw error
  }

  // convert DER to ASN.1 object
  return publicKeyFromAsn1(asn1.fromDer(msg.body))
}

/**
 * Converts an RSA public key to PEM format (using a SubjectPublicKeyInfo).
 *
 * @param key the public key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted public key.
 */
export function publicKeyToPem(key: any, maxline: number): string {
  // convert to ASN.1, then DER, then PEM-encode
  const msg = {
    type: 'PUBLIC KEY',
    body: asn1.toDer(publicKeyToAsn1(key)).getBytes(),
  }

  return pem.encode(msg, { maxline })
}

/**
 * Converts an RSA public key to PEM format (using an RSAPublicKey).
 *
 * @param key the public key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted public key.
 */
export function publicKeyToRSAPublicKeyPem(key: any, maxline: number): string {
  // convert to ASN.1, then DER, then PEM-encode
  const msg = {
    type: 'RSA PUBLIC KEY',
    body: asn1.toDer(publicKeyToAsn1(key)).getBytes(),
  }

  return pem.encode(msg, { maxline })
}

/**
 * Gets a fingerprint for the given public key.
 *
 * @param options the options to use.
 * @param options.md the message digest object to use (defaults to md.sha1).
 * @param options.type the type of fingerprint, such as 'RSAPublicKey', 'SubjectPublicKeyInfo' (defaults to 'RSAPublicKey').
 * @param options.encoding an alternative output encoding, such as 'hex' (defaults to none, outputs a byte buffer).
 * @param options.delimiter the delimiter to use between bytes for 'hex' encoded output, eg: ':' (defaults to none).
 *
 * @return the fingerprint as a byte buffer or other encoding based on options.
 */
export function getPublicKeyFingerprint(
  key: any,
  options: {
    md?: IMessageDigest
    type?: string
    encoding?: string
    delimiter?: string
  }
): string {
  options = options || {}
  options.type = options.type || 'RSAPublicKey'

  // use SHA-1 message digest by default
  options.md = options.md || (md.sha1.create() as unknown as IMessageDigest)

  // produce DER from RSAPublicKey and digest it
  const bytes = asn1.toDer(publicKeyToAsn1(key)).getBytes()
  options.md.update(bytes)

  const digest = options.md.digest()

  // encode as hex by default
  let rval
  if (options.encoding === 'hex') {
    rval = digest.toHex()
  }
  else if (options.encoding === 'binary') {
    rval = digest.getBytes()
  }
  else {
    rval = digest.toHex()
  }

  // add delimiter
  if (options.delimiter) {
    const hex = rval.match(/.{2}/g)
    if (hex) {
      rval = hex.join(options.delimiter)
    }
  }

  return rval
}

/**
 * Converts a PKCS#10 certification request (CSR) from PEM format.
 *
 * Note: If the certification request is to be verified then compute hash
 * should be set to true. This will scan the CertificationRequestInfo part of
 * the ASN.1 object while it is converted so it doesn't need to be converted
 * back to ASN.1-DER-encoding later.
 *
 * @param pem the PEM-formatted certificate.
 * @param computeHash true to compute the hash for verification.
 * @param strict true to be strict when checking ASN.1 value lengths, false to
 *          allow truncated values (default: true).
 *
 * @return the certification request (CSR).
 */
export function certificationRequestFromPem(
  pemString: string,
  computeHash: boolean,
  strict: boolean
): CertificationRequest {
  const msg = pem.decode(pemString)[0]

  if (msg.type !== 'CERTIFICATE REQUEST') {
    const error: CustomError = new Error('Could not convert certification request from PEM; PEM header type is not "CERTIFICATE REQUEST".')
    error.headerType = msg.type
    throw error
  }

  // convert DER to ASN.1 object
  return certificationRequestFromAsn1(asn1.fromDer(msg.body), computeHash)
}

/**
 * Converts a PKCS#10 certification request (CSR) to PEM format.
 *
 * @param csr the certification request.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted certification request.
 */
export function certificationRequestToPem(csr: CertificationRequest, maxline: number): string {
  // convert to ASN.1, then DER, then PEM-encode
  const msg = {
    type: 'CERTIFICATE REQUEST',
    body: asn1.toDer(certificationRequestToAsn1(csr)).getBytes(),
  }

  return pem.encode(msg, { maxline })
}

/**
 * Creates an empty X.509v3 RSA certificate.
 *
 * @return the certificate.
 */
export function createCertificate(): Certificate {
  const cert: Certificate = {
    version: 0x02,
    serialNumber: '00',
    signatureOid: null,
    signature: null,
    siginfo: {
      algorithmOid: null
    },
    validity: {
      notBefore: new Date(),
      notAfter: new Date()
    },
    issuer: {
      getField: function(sn: string) {
        return _getAttribute(cert.issuer, sn)
      },
      addField: function(attr: RDNAttribute) {
        _fillMissingFields([attr])
        cert.issuer.attributes.push(attr)
      },
      attributes: [],
      hash: null
    },
    subject: {
      getField: function(sn: string) {
        return _getAttribute(cert.subject, sn)
      },
      addField: function(attr: RDNAttribute) {
        _fillMissingFields([attr])
        cert.subject.attributes.push(attr)
      },
      attributes: [],
      hash: null
    },
    extensions: [],
    publicKey: null,
    md: null,
    issued: function(child: Certificate) {
      return child.isIssuer(cert)
    },
    isIssuer: function(parent: Certificate) {
      let rval = false
      const i = cert.issuer
      const s = parent.subject

      // compare hashes if present
      if (i.hash && s.hash)
        rval = (i.hash === s.hash)
      // if hashes are not present or not equal, compare attributes
      else {
        // ensure all parent subject attributes are present in issuer
        const iattr = i.attributes
        const sattr = s.attributes
        rval = _containsAll(iattr, sattr)
      }

      return rval
    },
    generateSubjectKeyIdentifier: function() {
      return getPublicKeyFingerprint(cert.publicKey, { type: 'RSAPublicKey' })
    },
    verifySubjectKeyIdentifier: function() {
      const oid = oids.subjectKeyIdentifier
      for (let i = 0; i < cert.extensions.length; ++i) {
        const ext = cert.extensions[i]
        if (ext.id === oid) {
          const ski = cert.generateSubjectKeyIdentifier().getBytes()
          return (hexToBytes(ext.subjectKeyIdentifier) === ski)
        }
      }
      return false
    },
  }

  return cert
}

/**
 * Converts an X.509v3 RSA certificate from an ASN.1 object.
 *
 * Note: If the certificate is to be verified then compute hash should be set to true. There is currently
 * no implementation for converting a certificate back to ASN.1 so the TBSCertificate
 * part of the ASN.1 object needs to be scanned before the cert object is created.
 *
 * @param obj the asn1 representation of an X.509v3 RSA certificate.
 * @param computeHash true to compute the hash for verification.
 *
 * @return the certificate.
 */
export function certificateFromAsn1(obj: any, computeHash: boolean): Certificate {
  // validate certificate and capture data
  const capture: CaptureObject = {}
  const errors: CustomError[] = []

  if (!asn1.validate(obj, x509CertificateValidator, capture, errors)) {
    const error: CustomError = new Error('Cannot read X.509 certificate. ASN.1 object is not an X509v3 Certificate.')
    error.errors = errors
    throw error
  }

  // get oid
  const oid = asn1.derToOid(capture.publicKeyOid)
  if (oid !== oids.rsaEncryption)
    throw new Error('Cannot read public key. OID is not RSA.')

  // create certificate
  const cert = createCertificate()
  cert.version = capture.certVersion ? capture.certVersion.charCodeAt(0) : 0
  const serial = util.createBuffer(capture.certSerialNumber)
  cert.serialNumber = serial.toHex()
  cert.signatureOid = asn1.derToOid(capture.certSignatureOid)
  cert.signatureParameters = readSignatureParameters(
    cert.signatureOid,
    capture.certSignatureParams,
    true
  )
  cert.siginfo.algorithmOid = asn1.derToOid(capture.certinfoSignatureOid)
  cert.siginfo.parameters = readSignatureParameters(
    cert.siginfo.algorithmOid,
    capture.certinfoSignatureParams,
    false
  )
  cert.signature = capture.certSignature

  const validity = []
  if (capture.certValidity1UTCTime !== undefined)
    validity.push(asn1.utcTimeToDate(capture.certValidity1UTCTime))

  if (capture.certValidity2GeneralizedTime !== undefined) {
    validity.push(asn1.generalizedTimeToDate(
      capture.certValidity2GeneralizedTime,
    ))
  }

  if (capture.certValidity3UTCTime !== undefined)
    validity.push(asn1.utcTimeToDate(capture.certValidity3UTCTime))

  if (capture.certValidity4GeneralizedTime !== undefined) {
    validity.push(asn1.generalizedTimeToDate(
      capture.certValidity4GeneralizedTime,
    ))
  }

  if (validity.length > 2)
    throw new Error('Cannot read notBefore/notAfter validity times; more than two times were provided in the certificate.')
  if (validity.length < 2)
    throw new Error('Cannot read notBefore/notAfter validity times; they were not provided as either UTCTime or GeneralizedTime.')

  cert.validity.notBefore = validity[0]
  cert.validity.notAfter = validity[1]

  // keep TBSCertificate to preserve signature when exporting
  cert.tbsCertificate = capture.tbsCertificate

  if (computeHash) {
    // create digest for OID signature type
    cert.md = _createSignatureDigest({
      signatureOid: cert.signatureOid,
      type: 'certificate',
    })

    // produce DER formatted TBSCertificate and digest it
    const bytes = asn1.toDer(cert.tbsCertificate)
    cert.md.update(bytes.getBytes())
  }

  // handle issuer, build issuer message digest
  const imd = md.sha1.create()
  const ibytes = asn1.toDer(capture.certIssuer)
  imd.update(ibytes.getBytes())
  cert.issuer.getField = function (sn) {
    return _getAttribute(cert.issuer, sn)
  }
  cert.issuer.addField = function (attr) {
    _fillMissingFields([attr])
    cert.issuer.attributes.push(attr)
  }
  cert.issuer.attributes = RDNAttributesAsArray(capture.certIssuer)
  if (capture.certIssuerUniqueId) {
    cert.issuer.uniqueId = capture.certIssuerUniqueId
  }
  cert.issuer.hash = imd.digest().toHex()

  // handle subject, build subject message digest
  const smd = md.sha1.create()
  const sbytes = asn1.toDer(capture.certSubject)
  smd.update(sbytes.getBytes())
  cert.subject.getField = function (sn) {
    return _getAttribute(cert.subject, sn)
  }
  cert.subject.addField = function (attr) {
    _fillMissingFields([attr])
    cert.subject.attributes.push(attr)
  }
  cert.subject.attributes = RDNAttributesAsArray(capture.certSubject)
  if (capture.certSubjectUniqueId)
    cert.subject.uniqueId = capture.certSubjectUniqueId

  cert.subject.hash = smd.digest().toHex()

  // handle extensions
  if (capture.certExtensions) {
    cert.extensions = certificateExtensionsFromAsn1(capture.certExtensions)
  }
  else {
    cert.extensions = []
  }

  // convert RSA public key from ASN.1
  cert.publicKey = publicKeyFromAsn1(capture.subjectPublicKeyInfo)

  return cert
}

/**
 * Converts an ASN.1 extensions object (with extension sequences as its
 * values) into an array of extension objects with types and values.
 *
 * Supported extensions:
 *
 * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 * KeyUsage ::= BIT STRING {
 *   digitalSignature        (0),
 *   nonRepudiation          (1),
 *   keyEncipherment         (2),
 *   dataEncipherment        (3),
 *   keyAgreement            (4),
 *   keyCertSign             (5),
 *   cRLSign                 (6),
 *   encipherOnly            (7),
 *   decipherOnly            (8)
 * }
 *
 * id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
 * BasicConstraints ::= SEQUENCE {
 *   cA                      BOOLEAN DEFAULT FALSE,
 *   pathLenConstraint       INTEGER (0..MAX) OPTIONAL
 * }
 *
 * subjectAltName EXTENSION ::= {
 *   SYNTAX GeneralNames
 *   IDENTIFIED BY id-ce-subjectAltName
 * }
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *   otherName      [0] INSTANCE OF OTHER-NAME,
 *   rfc822Name     [1] IA5String,
 *   dNSName        [2] IA5String,
 *   x400Address    [3] ORAddress,
 *   directoryName  [4] Name,
 *   ediPartyName   [5] EDIPartyName,
 *   uniformResourceIdentifier [6] IA5String,
 *   IPAddress      [7] OCTET STRING,
 *   registeredID   [8] OBJECT IDENTIFIER
 * }
 *
 * OTHER-NAME ::= TYPE-IDENTIFIER
 *
 * EDIPartyName ::= SEQUENCE {
 *   nameAssigner [0] DirectoryString {ub-name} OPTIONAL,
 *   partyName    [1] DirectoryString {ub-name}
 * }
 *
 * @param exts the extensions ASN.1 with extension sequences to parse.
 *
 * @return the array.
 */
export function certificateExtensionsFromAsn1(exts: Asn1Object): CertificateExtension[] {
  const rval = []

  for (let i = 0; i < exts.value.length; ++i) {
    // get extension sequence
    const extseq = exts.value[i]
    for (let ei = 0; ei < extseq.value.length; ++ei) {
      rval.push(certificateExtensionFromAsn1(extseq.value[ei]))
    }
  }

  return rval
}

/**
 * Parses a single certificate extension from ASN.1.
 *
 * @param ext the extension in ASN.1 format.
 *
 * @return the parsed extension as an object.
 */
export function certificateExtensionFromAsn1(ext: Asn1Object): CertificateExtension {
  // an extension has:
  // [0] extnID      OBJECT IDENTIFIER
  // [1] critical    BOOLEAN DEFAULT FALSE
  // [2] extnValue   OCTET STRING
  const e: CertificateExtension = {
    id: asn1.derToOid(ext.value[0].value),
    critical: false,
    value: null
  }

  if (ext.value[1].type === asn1.Type.BOOLEAN) {
    e.critical = (ext.value[1].value.charCodeAt(0) !== 0x00)
    e.value = ext.value[2].value
  }
  else {
    e.value = ext.value[1].value
  }
  // if the oid is known, get its name
  if (e.id in oids) {
    e.name = oids[e.id]

    // handle key usage
    if (e.name === 'keyUsage') {
      // get value as BIT STRING
      var ev = asn1.fromDer(e.value)
      var b2 = 0x00
      let b3 = 0x00
      if (ev.value.length > 1) {
        // skip first byte, just indicates unused bits which
        // will be padded with 0s anyway
        // get bytes with flag bits
        b2 = ev.value.charCodeAt(1)
        b3 = ev.value.length > 2 ? ev.value.charCodeAt(2) : 0
      }
      // set flags
      e.digitalSignature = (b2 & 0x80) === 0x80
      e.nonRepudiation = (b2 & 0x40) === 0x40
      e.keyEncipherment = (b2 & 0x20) === 0x20
      e.dataEncipherment = (b2 & 0x10) === 0x10
      e.keyAgreement = (b2 & 0x08) === 0x08
      e.keyCertSign = (b2 & 0x04) === 0x04
      e.cRLSign = (b2 & 0x02) === 0x02
      e.encipherOnly = (b2 & 0x01) === 0x01
      e.decipherOnly = (b3 & 0x80) === 0x80
    }
    else if (e.name === 'basicConstraints') {
      // handle basic constraints
      // get value as SEQUENCE
      var ev = asn1.fromDer(e.value)
      // get cA BOOLEAN flag (defaults to false)
      if (ev.value.length > 0 && ev.value[0].type === asn1.Type.BOOLEAN) {
        e.cA = (ev.value[0].value.charCodeAt(0) !== 0x00)
      }
      else {
        e.cA = false
      }
      // get path length constraint
      let value = null
      if (ev.value.length > 0 && ev.value[0].type === asn1.Type.INTEGER) {
        value = ev.value[0].value
      }
      else if (ev.value.length > 1) {
        value = ev.value[1].value
      }
      if (value !== null) {
        e.pathLenConstraint = asn1.derToInteger(value)
      }
    }
    else if (e.name === 'extKeyUsage') {
      // handle extKeyUsage
      // value is a SEQUENCE of OIDs
      var ev = asn1.fromDer(e.value)
      for (let vi = 0; vi < ev.value.length; ++vi) {
        const oid = asn1.derToOid(ev.value[vi].value)
        if (oid in oids) {
          e[oids[oid]] = true
        }
        else {
          e[oid] = true
        }
      }
    }
    else if (e.name === 'nsCertType') {
      // handle nsCertType
      // get value as BIT STRING
      var ev = asn1.fromDer(e.value)
      var b2 = 0x00
      if (ev.value.length > 1) {
        // skip first byte, just indicates unused bits which
        // will be padded with 0s anyway
        // get bytes with flag bits
        b2 = ev.value.charCodeAt(1)
      }
      // set flags
      e.client = (b2 & 0x80) === 0x80
      e.server = (b2 & 0x40) === 0x40
      e.email = (b2 & 0x20) === 0x20
      e.objsign = (b2 & 0x10) === 0x10
      e.reserved = (b2 & 0x08) === 0x08
      e.sslCA = (b2 & 0x04) === 0x04
      e.emailCA = (b2 & 0x02) === 0x02
      e.objCA = (b2 & 0x01) === 0x01
    }
    else if (
      e.name === 'subjectAltName'
      || e.name === 'issuerAltName') {
      // handle subjectAltName/issuerAltName
      e.altNames = []

      // ev is a SYNTAX SEQUENCE
      let gn
      var ev = asn1.fromDer(e.value)
      for (let n = 0; n < ev.value.length; ++n) {
        // get GeneralName
        gn = ev.value[n]

        const altName: AltName = {
          type: gn.type,
          value: gn.value,
        }
        e.altNames.push(altName)

        // Note: Support for types 1,2,6,7,8
        switch (gn.type) {
          // rfc822Name
          case 1:
          // dNSName
          case 2:
          // uniformResourceIdentifier (URI)
          case 6:
            break
          // IPAddress
          case 7:
            // convert to IPv4/IPv6 string representation
            altName.ip = util.bytesToIP(gn.value)
            break
          // registeredID
          case 8:
            altName.oid = asn1.derToOid(gn.value)
            break
          default:
            // unsupported
        }
      }
    }
    else if (e.name === 'subjectKeyIdentifier') {
      // value is an OCTETSTRING w/the hash of the key-type specific
      // public key structure (eg: RSAPublicKey)
      const ev = asn1.fromDer(e.value)
      e.subjectKeyIdentifier = util.bytesToHex(ev.value)
    }
  }

  return e
}

type CertificationRequestCapture = {
  csrVersion?: string
  csrSignatureOid?: string
  csrSignatureParams?: string
  csrSignature?: string
  certificationRequestInfo?: Asn1Object
  publicKeyOid?: string
  subjectPublicKeyInfo?: Asn1Object
  certificationRequestInfoSubject?: Asn1Object
  certificationRequestInfoAttributes?: Asn1Object[]
}

/**
 * Converts a PKCS#10 certification request (CSR) from an ASN.1 object.
 *
 * Note: If the certification request is to be verified then compute hash
 * should be set to true. There is currently no implementation for converting
 * a certificate back to ASN.1 so the CertificationRequestInfo part of the
 * ASN.1 object needs to be scanned before the csr object is created.
 *
 * @param obj the asn1 representation of a PKCS#10 certification request (CSR).
 * @param computeHash true to compute the hash for verification.
 *
 * @return the certification request (CSR).
 */
export function certificationRequestFromAsn1(obj: Asn1Object, computeHash: boolean): CertificationRequest {
  // validate certification request and capture data
  const capture: CertificationRequestCapture = {}
  const errors: CustomError[] = []

  if (!asn1.validate(obj, certificationRequestValidator, capture, errors)) {
    const error: CustomError = new Error('Cannot read PKCS#10 certificate request. ASN.1 object is not a PKCS#10 CertificationRequest.')
    error.errors = errors
    throw error
  }

  // get oid
  const oid = asn1.derToOid(capture.publicKeyOid)
  if (oid !== oids.rsaEncryption)
    throw new Error('Cannot read public key. OID is not RSA.')

  // create certification request
  const csr = createCertificationRequest()
  csr.version = capture.csrVersion ? capture.csrVersion.charCodeAt(0) : 0
  csr.signatureOid = asn1.derToOid(capture.csrSignatureOid)
  csr.signatureParameters = readSignatureParameters(
    csr.signatureOid,
    capture.csrSignatureParams,
    true,
  )
  csr.siginfo.algorithmOid = asn1.derToOid(capture.csrSignatureOid)
  csr.siginfo.parameters = readSignatureParameters(
    csr.siginfo.algorithmOid,
    capture.csrSignatureParams,
    false,
  )
  csr.signature = capture.csrSignature

  // keep CertificationRequestInfo to preserve signature when exporting
  csr.certificationRequestInfo = capture.certificationRequestInfo

  if (computeHash) {
    // create digest for OID signature type
    csr.md = _createSignatureDigest({
      signatureOid: csr.signatureOid,
      type: 'certification request',
    })

    // produce DER formatted CertificationRequestInfo and digest it
    const bytes = asn1.toDer(csr.certificationRequestInfo)
    csr.md.update(bytes.getBytes())
  }

  // handle subject, build subject message digest
  const smd = md.sha1.create()
  csr.subject.getField = function (sn) {
    return _getAttribute(csr.subject, sn)
  }
  csr.subject.addField = function (attr) {
    _fillMissingFields([attr])
    csr.subject.attributes.push(attr)
  }
  csr.subject.attributes = RDNAttributesAsArray(
    capture.certificationRequestInfoSubject,
    smd,
  )
  csr.subject.hash = smd.digest().toHex()

  // convert RSA public key from ASN.1
  csr.publicKey = publicKeyFromAsn1(capture.subjectPublicKeyInfo)

  // convert attributes from ASN.1
  csr.getAttribute = function (sn) {
    return _getAttribute(csr, sn)
  }
  csr.addAttribute = function (attr) {
    _fillMissingFields([attr])
    csr.attributes.push(attr)
  }
  csr.attributes = pki.CRIAttributesAsArray(
    capture.certificationRequestInfoAttributes || [],
  )

  return csr
}

/**
 * Creates an empty certification request (a CSR or certificate signing
 * request). Once created, its public key and attributes can be set and then
 * it can be signed.
 *
 * @return the empty certification request.
 */
export function createCertificationRequest(): CertificationRequest {
  const csr = {}
  csr.version = 0x00
  csr.signatureOid = null
  csr.signature = null
  csr.siginfo = {}
  csr.siginfo.algorithmOid = null

  csr.subject = {}
  csr.subject.getField = function (sn) {
    return _getAttribute(csr.subject, sn)
  }
  csr.subject.addField = function (attr) {
    _fillMissingFields([attr])
    csr.subject.attributes.push(attr)
  }
  csr.subject.attributes = []
  csr.subject.hash = null

  csr.publicKey = null
  csr.attributes = []
  csr.getAttribute = function (sn) {
    return _getAttribute(csr, sn)
  }
  csr.addAttribute = function (attr) {
    _fillMissingFields([attr])
    csr.attributes.push(attr)
  }
  csr.md = null

  /**
   * Sets the subject of this certification request.
   *
   * @param attrs the array of subject attributes to use.
   */
  csr.setSubject = function (attrs) {
    // set new attributes
    _fillMissingFields(attrs)
    csr.subject.attributes = attrs
    csr.subject.hash = null
  }

  /**
   * Sets the attributes of this certification request.
   *
   * @param attrs the array of attributes to use.
   */
  csr.setAttributes = function (attrs) {
    // set new attributes
    _fillMissingFields(attrs)
    csr.attributes = attrs
  }

  /**
   * Signs this certification request using the given private key.
   *
   * @param key the private key to sign with.
   * @param md the message digest object to use (defaults to md.sha1).
   */
  csr.sign = function (key, md) {
    // TODO: get signature OID from private key
    csr.md = md || md.sha1.create()
    const algorithmOid = oids[`${csr.md.algorithm}WithRSAEncryption`]
    if (!algorithmOid) {
      const error = new Error('Could not compute certification request digest. '
        + 'Unknown message digest algorithm OID.')
      error.algorithm = csr.md.algorithm
      throw error
    }
    csr.signatureOid = csr.siginfo.algorithmOid = algorithmOid

    // get CertificationRequestInfo, convert to DER
    csr.certificationRequestInfo = pki.getCertificationRequestInfo(csr)
    const bytes = asn1.toDer(csr.certificationRequestInfo)

    // digest and sign
    csr.md.update(bytes.getBytes())
    csr.signature = key.sign(csr.md)
  }

  /**
   * Attempts verify the signature on the passed certification request using
   * its public key.
   *
   * A CSR that has been exported to a file in PEM format can be verified using
   * OpenSSL using this command:
   *
   * openssl req -in <the-csr-pem-file> -verify -noout -text
   *
   * @return true if verified, false if not.
   */
  csr.verify = function () {
    let rval = false

    let md = csr.md
    if (md === null) {
      md = _createSignatureDigest({
        signatureOid: csr.signatureOid,
        type: 'certification request',
      })

      // produce DER formatted CertificationRequestInfo and digest it
      const cri = csr.certificationRequestInfo
        || pki.getCertificationRequestInfo(csr)
      const bytes = asn1.toDer(cri)
      md.update(bytes.getBytes())
    }

    if (md !== null) {
      export rval = verifySignature({
        certificate: csr,
        md,
        signature: csr.signature,
      })
    }

    return rval
  }

  return csr
}

/**
 * Converts an X.509 subject or issuer to an ASN.1 RDNSequence.
 *
 * @param obj the subject or issuer (distinguished name).
 *
 * @return the ASN.1 RDNSequence.
 */
function _dnToAsn1(obj) {
  // create an empty RDNSequence
  const rval = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.SEQUENCE,
    true,
    [],
  )

  // iterate over attributes
  let attr, set
  const attrs = obj.attributes
  for (let i = 0; i < attrs.length; ++i) {
    attr = attrs[i]
    let value = attr.value

    // reuse tag class for attribute value if available
    let valueTagClass = asn1.Type.PRINTABLESTRING
    if ('valueTagClass' in attr) {
      valueTagClass = attr.valueTagClass

      if (valueTagClass === asn1.Type.UTF8)
        value = util.encodeUtf8(value)

      // FIXME: handle more encodings
    }

    // create a RelativeDistinguishedName set
    // each value in the set is an AttributeTypeAndValue first
    // containing the type (an OID) and second the value
    set = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // AttributeType
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(attr.type).getBytes()),
        // AttributeValue
        asn1.create(asn1.Class.UNIVERSAL, valueTagClass, false, value),
      ]),
    ])
    rval.value.push(set)
  }

  return rval
}

/**
 * Gets all printable attributes (typically of an issuer or subject) in a
 * simplified JSON format for display.
 *
 * @param attrs the attributes.
 *
 * @return the JSON for display.
 */
function _getAttributesAsJson(attrs) {
  const rval = {}
  for (let i = 0; i < attrs.length; ++i) {
    const attr = attrs[i]
    if (attr.shortName && (
      attr.valueTagClass === asn1.Type.UTF8
      || attr.valueTagClass === asn1.Type.PRINTABLESTRING
      || attr.valueTagClass === asn1.Type.IA5STRING)) {
      let value = attr.value
      if (attr.valueTagClass === asn1.Type.UTF8) {
        value = util.encodeUtf8(attr.value)
      }
      if (!(attr.shortName in rval)) {
        rval[attr.shortName] = value
      }
      else if (Array.isArray(rval[attr.shortName])) {
        rval[attr.shortName].push(value)
      }
      else {
        rval[attr.shortName] = [rval[attr.shortName], value]
      }
    }
  }
  return rval
}

/**
 * Fills in missing fields in attributes.
 *
 * @param attrs the attributes to fill missing fields in.
 */
function _fillMissingFields(attrs) {
  let attr
  for (let i = 0; i < attrs.length; ++i) {
    attr = attrs[i]

    // populate missing name
    if (typeof attr.name === 'undefined') {
      if (attr.type && attr.type in oids) {
        attr.name = oids[attr.type]
      }
      else if (attr.shortName && attr.shortName in _shortNames) {
        attr.name = oids[_shortNames[attr.shortName]]
      }
    }

    // populate missing type (OID)
    if (typeof attr.type === 'undefined') {
      if (attr.name && attr.name in oids) {
        attr.type = oids[attr.name]
      }
      else {
        var error = new Error('Attribute type not specified.')
        error.attribute = attr
        throw error
      }
    }

    // populate missing shortname
    if (typeof attr.shortName === 'undefined') {
      if (attr.name && attr.name in _shortNames) {
        attr.shortName = _shortNames[attr.name]
      }
    }

    // convert extensions to value
    if (attr.type === oids.extensionRequest && attr.extensions) {
      attr.valueTagClass = asn1.Type.SEQUENCE
      attr.valueConstructed = true
      attr.value = []
      for (const ext of attr.extensions) {
        attr.value.push(certificateExtensionToAsn1(_fillMissingExtensionFields(ext)))
      }
    }

    if (typeof attr.value === 'undefined') {
      var error = new Error('Attribute value not specified.')
      error.attribute = attr
      throw error
    }
  }
}

/**
 * Fills in missing fields in certificate extensions.
 *
 * @param e the extension.
 * @param [options] the options to use.
 *          [cert] the certificate the extensions are for.
 *
 * @return the extension.
 */
function _fillMissingExtensionFields(e, options) {
  options = options || {}

  // populate missing name
  if (typeof e.name === 'undefined') {
    if (e.id && e.id in oids) {
      e.name = oids[e.id]
    }
  }

  // populate missing id
  if (typeof e.id === 'undefined') {
    if (e.name && e.name in oids) {
      e.id = oids[e.name]
    }
    else {
      const error: CustomError = new Error('Extension ID not specified.')
      error.extension = e
      throw error
    }
  }

  if (typeof e.value !== 'undefined') {
    return e
  }

  // handle missing value:

  // value is a BIT STRING
  if (e.name === 'keyUsage') {
    // build flags
    var unused = 0
    var b2 = 0x00
    let b3 = 0x00
    if (e.digitalSignature) {
      b2 |= 0x80
      unused = 7
    }
    if (e.nonRepudiation) {
      b2 |= 0x40
      unused = 6
    }
    if (e.keyEncipherment) {
      b2 |= 0x20
      unused = 5
    }
    if (e.dataEncipherment) {
      b2 |= 0x10
      unused = 4
    }
    if (e.keyAgreement) {
      b2 |= 0x08
      unused = 3
    }
    if (e.keyCertSign) {
      b2 |= 0x04
      unused = 2
    }
    if (e.cRLSign) {
      b2 |= 0x02
      unused = 1
    }
    if (e.encipherOnly) {
      b2 |= 0x01
      unused = 0
    }
    if (e.decipherOnly) {
      b3 |= 0x80
      unused = 7
    }

    // create bit string
    var value = String.fromCharCode(unused)
    if (b3 !== 0) {
      value += String.fromCharCode(b2) + String.fromCharCode(b3)
    }
    else if (b2 !== 0) {
      value += String.fromCharCode(b2)
    }
    e.value = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.BITSTRING,
      false,
      value,
    )
  }
  else if (e.name === 'basicConstraints') {
    // basicConstraints is a SEQUENCE
    e.value = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.SEQUENCE,
      true,
      [],
    )
    // cA BOOLEAN flag defaults to false
    if (e.cA) {
      e.value.value.push(asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.BOOLEAN,
        false,
        String.fromCharCode(0xFF),
      ))
    }
    if ('pathLenConstraint' in e) {
      e.value.value.push(asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.INTEGER,
        false,
        asn1.integerToDer(e.pathLenConstraint).getBytes(),
      ))
    }
  }
  else if (e.name === 'extKeyUsage') {
    // extKeyUsage is a SEQUENCE of OIDs
    e.value = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.SEQUENCE,
      true,
      [],
    )
    var seq = e.value.value
    for (const key in e) {
      if (e[key] !== true) {
        continue
      }
      // key is name in OID map
      if (key in oids) {
        seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(oids[key]).getBytes()))
      }
      else if (key.includes('.')) {
        // assume key is an OID
        seq.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(key).getBytes()))
      }
    }
  }
  else if (e.name === 'nsCertType') {
    // nsCertType is a BIT STRING
    // build flags
    let unused = 0
    let b2 = 0x00

    if (e.client) {
      b2 |= 0x80
      unused = 7
    }
    if (e.server) {
      b2 |= 0x40
      unused = 6
    }
    if (e.email) {
      b2 |= 0x20
      unused = 5
    }
    if (e.objsign) {
      b2 |= 0x10
      unused = 4
    }
    if (e.reserved) {
      b2 |= 0x08
      unused = 3
    }
    if (e.sslCA) {
      b2 |= 0x04
      unused = 2
    }
    if (e.emailCA) {
      b2 |= 0x02
      unused = 1
    }
    if (e.objCA) {
      b2 |= 0x01
      unused = 0
    }

    // create bit string
    var value = String.fromCharCode(unused)
    if (b2 !== 0) {
      value += String.fromCharCode(b2)
    }
    e.value = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.BITSTRING,
      false,
      value,
    )
  }
  else if (e.name === 'subjectAltName' || e.name === 'issuerAltName') {
    // SYNTAX SEQUENCE
    e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [])

    let altName
    for (let n = 0; n < e.altNames.length; ++n) {
      altName = e.altNames[n]
      let value = altName.value
      // handle IP
      if (altName.type === 7 && altName.ip) {
        value = util.bytesFromIP(altName.ip)
        if (value === null) {
          const error: CustomError = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.')
          error.extension = e
          throw error
        }
      }
      else if (altName.type === 8) {
        // handle OID
        if (altName.oid) {
          value = asn1.oidToDer(asn1.oidToDer(altName.oid))
        }
        else {
          // deprecated ... convert value to OID
          value = asn1.oidToDer(value)
        }
      }
      e.value.value.push(asn1.create(
        asn1.Class.CONTEXT_SPECIFIC,
        altName.type,
        false,
        value,
      ))
    }
  }
  else if (e.name === 'nsComment' && options.cert) {
    // sanity check value is ASCII (req'd) and not too big
    if (!(/^[\x00-\x7F]*$/.test(e.comment))
      || (e.comment.length < 1) || (e.comment.length > 128)) {
      throw new Error('Invalid "nsComment" content.')
    }
    // IA5STRING opaque comment
    e.value = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.IA5STRING,
      false,
      e.comment,
    )
  }
  else if (e.name === 'subjectKeyIdentifier' && options.cert) {
    const ski = options.cert.generateSubjectKeyIdentifier()
    e.subjectKeyIdentifier = ski.toHex()
    // OCTETSTRING w/digest
    e.value = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.OCTETSTRING,
      false,
      ski.getBytes(),
    )
  }
  else if (e.name === 'authorityKeyIdentifier' && options.cert) {
    // SYNTAX SEQUENCE
    e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [])
    const seq = e.value.value

    if (e.keyIdentifier) {
      const keyIdentifier = (e.keyIdentifier === true
        ? options.cert.generateSubjectKeyIdentifier().getBytes()
        : e.keyIdentifier)
      seq.push(
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, false, keyIdentifier),
      )
    }

    if (e.authorityCertIssuer) {
      const authorityCertIssuer = [
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 4, true, [
          _dnToAsn1(e.authorityCertIssuer === true
            ? options.cert.issuer
            : e.authorityCertIssuer),
        ]),
      ]
      seq.push(
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, authorityCertIssuer),
      )
    }

    if (e.serialNumber) {
      const serialNumber = hexToBytes(e.serialNumber === true
        ? options.cert.serialNumber
        : e.serialNumber)
      seq.push(
        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, false, serialNumber),
      )
    }
  }
  else if (e.name === 'cRLDistributionPoints') {
    e.value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [])
    var seq = e.value.value

    // Create sub SEQUENCE of DistributionPointName
    const subSeq = asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.SEQUENCE,
      true,
      [],
    )

    // Create fullName CHOICE
    const fullNameGeneralNames = asn1.create(
      asn1.Class.CONTEXT_SPECIFIC,
      0,
      true,
      [],
    )
    let altName
    for (let n = 0; n < e.altNames.length; ++n) {
      altName = e.altNames[n]
      let value = altName.value
      // handle IP
      if (altName.type === 7 && altName.ip) {
        value = util.bytesFromIP(altName.ip)
        if (value === null) {
          const error: CustomError = new Error('Extension "ip" value is not a valid IPv4 or IPv6 address.')
          error.extension = e
          throw error
        }
      }
      else if (altName.type === 8) {
        // handle OID
        if (altName.oid) {
          value = asn1.oidToDer(asn1.oidToDer(altName.oid))
        }
        else {
          // deprecated ... convert value to OID
          value = asn1.oidToDer(value)
        }
      }
      fullNameGeneralNames.value.push(asn1.create(
        asn1.Class.CONTEXT_SPECIFIC,
        altName.type,
        false,
        value,
      ))
    }

    // Add to the parent SEQUENCE
    subSeq.value.push(asn1.create(
      asn1.Class.CONTEXT_SPECIFIC,
      0,
      true,
      [fullNameGeneralNames],
    ))
    seq.push(subSeq)
  }

  // ensure value has been defined by now
  if (typeof e.value === 'undefined') {
    const error: CustomError = new Error('Extension value not specified.')
    error.extension = e
    throw error
  }

  return e
}

/**
 * Convert signature parameters object to ASN.1
 *
 * @param {string} oid Signature algorithm OID
 * @param params The signature parametrs object
 * @return ASN.1 object representing signature parameters
 */
function _signatureParametersToAsn1(oid, params) {
  switch (oid) {
    case oids['RSASSA-PSS']:
      const parts = []

      if (params.hash.algorithmOid !== undefined) {
        parts.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(params.hash.algorithmOid).getBytes()),
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
          ]),
        ]))
      }

      if (params.mgf.algorithmOid !== undefined) {
        parts.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(params.mgf.algorithmOid).getBytes()),
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(params.mgf.hash.algorithmOid).getBytes()),
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
            ]),
          ]),
        ]))
      }

      if (params.saltLength !== undefined) {
        parts.push(asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(params.saltLength).getBytes()),
        ]))
      }

      return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, parts)

    default:
      return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
  }
}

/**
 * Converts a certification request's attributes to an ASN.1 set of
 * CRIAttributes.
 *
 * @param csr certification request.
 *
 * @return the ASN.1 set of CRIAttributes.
 */
function _CRIAttributesToAsn1(csr) {
  // create an empty context-specific container
  const rval = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [])

  // no attributes, return empty container
  if (csr.attributes.length === 0) {
    return rval
  }

  // each attribute has a sequence with a type and a set of values
  const attrs = csr.attributes
  for (let i = 0; i < attrs.length; ++i) {
    const attr = attrs[i]
    let value = attr.value

    // reuse tag class for attribute value if available
    let valueTagClass = asn1.Type.UTF8
    if ('valueTagClass' in attr) {
      valueTagClass = attr.valueTagClass
    }
    if (valueTagClass === asn1.Type.UTF8) {
      value = util.encodeUtf8(value)
    }
    let valueConstructed = false
    if ('valueConstructed' in attr) {
      valueConstructed = attr.valueConstructed
    }
    // FIXME: handle more encodings

    // create a RelativeDistinguishedName set
    // each value in the set is an AttributeTypeAndValue first
    // containing the type (an OID) and second the value
    const seq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // AttributeType
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(attr.type).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
        // AttributeValue
        asn1.create(
          asn1.Class.UNIVERSAL,
          valueTagClass,
          valueConstructed,
          value,
        ),
      ]),
    ])
    rval.value.push(seq)
  }

  return rval
}

const jan_1_1950 = new Date('1950-01-01')
const jan_1_2050 = new Date('2050-01-01')

/**
 * Converts a Date object to ASN.1
 * Handles the different format before and after 1st January 2050
 *
 * @param date date object.
 *
 * @return the ASN.1 object representing the date.
 */
function _dateToAsn1(date) {
  if (date >= jan_1_1950 && date < jan_1_2050) {
    return asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.UTCTIME,
      false,
      asn1.dateToUtcTime(date),
    )
  }
  else {
    return asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.GENERALIZEDTIME,
      false,
      asn1.dateToGeneralizedTime(date),
    )
  }
}

/**
 * Gets the ASN.1 TBSCertificate part of an X.509v3 certificate.
 *
 * @param cert the certificate.
 *
 * @return the asn1 TBSCertificate.
 */
export function getTBSCertificate(cert: Certificate): any {
  // TBSCertificate
  const notBefore = _dateToAsn1(cert.validity.notBefore)
  const notAfter = _dateToAsn1(cert.validity.notAfter)
  const tbs = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version
    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      // integer
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(cert.version).getBytes()),
    ]),
    // serialNumber
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, hexToBytes(cert.serialNumber)),
    // signature
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(cert.siginfo.algorithmOid).getBytes()),
      // parameters
      _signatureParametersToAsn1(
        cert.siginfo.algorithmOid,
        cert.siginfo.parameters,
      ),
    ]),
    // issuer
    _dnToAsn1(cert.issuer),
    // validity
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      notBefore,
      notAfter,
    ]),
    // subject
    _dnToAsn1(cert.subject),
    // SubjectPublicKeyInfo
    publicKeyToAsn1(cert.publicKey),
  ])

  if (cert.issuer.uniqueId) {
    // issuerUniqueID (optional)
    tbs.value.push(
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
          // TODO: support arbitrary bit length ids
          String.fromCharCode(0x00)
          + cert.issuer.uniqueId),
      ]),
    )
  }
  if (cert.subject.uniqueId) {
    // subjectUniqueID (optional)
    tbs.value.push(
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 2, true, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
          // TODO: support arbitrary bit length ids
          String.fromCharCode(0x00)
          + cert.subject.uniqueId),
      ]),
    )
  }

  if (cert.extensions.length > 0) {
    // extensions (optional)
    tbs.value.push(pki.certificateExtensionsToAsn1(cert.extensions))
  }

  return tbs
}

/**
 * Gets the ASN.1 CertificationRequestInfo part of a
 * PKCS#10 CertificationRequest.
 *
 * @param csr the certification request.
 *
 * @return the asn1 CertificationRequestInfo.
 */
export function getCertificationRequestInfo(csr) {
  // CertificationRequestInfo
  const cri = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, asn1.integerToDer(csr.version).getBytes()),
    // subject
    _dnToAsn1(csr.subject),
    // SubjectPublicKeyInfo
    publicKeyToAsn1(csr.publicKey),
    // attributes
    _CRIAttributesToAsn1(csr),
  ])

  return cri
}

/**
 * Converts a DistinguishedName (subject or issuer) to an ASN.1 object.
 *
 * @param dn the DistinguishedName.
 *
 * @return the asn1 representation of a DistinguishedName.
 */
export function distinguishedNameToAsn1(dn) {
  return _dnToAsn1(dn)
}

/**
 * Converts an X.509v3 RSA certificate to an ASN.1 object.
 *
 * @param cert the certificate.
 *
 * @return the asn1 representation of an X.509v3 RSA certificate.
 */
export function certificateToAsn1(cert) {
  // prefer cached TBSCertificate over generating one
  const tbsCertificate = cert.tbsCertificate || getTBSCertificate(cert)

  // Certificate
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // TBSCertificate
    tbsCertificate,
    // AlgorithmIdentifier (signature algorithm)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(cert.signatureOid).getBytes()),
      // parameters
      _signatureParametersToAsn1(cert.signatureOid, cert.signatureParameters),
    ]),
    // SignatureValue
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, String.fromCharCode(0x00) + cert.signature),
  ])
}

/**
 * Converts X.509v3 certificate extensions to ASN.1.
 *
 * @param exts the extensions to convert.
 *
 * @return the extensions in ASN.1 format.
 */
export function certificateExtensionsToAsn1(exts) {
  // create top-level extension container
  const rval = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 3, true, [])

  // create extension sequence (stores a sequence for each extension)
  const seq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [])
  rval.value.push(seq)

  for (let i = 0; i < exts.length; ++i) {
    seq.value.push(certificateExtensionToAsn1(exts[i]))
  }

  return rval
}

/**
 * Converts a single certificate extension to ASN.1.
 *
 * @param ext the extension to convert.
 *
 * @return the extension in ASN.1 format.
 */
export function certificateExtensionToAsn1(ext) {
  // create a sequence for each extension
  const extseq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [])

  // extnID (OID)
  extseq.value.push(asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.OID,
    false,
    asn1.oidToDer(ext.id).getBytes(),
  ))

  // critical defaults to false
  if (ext.critical) {
    // critical BOOLEAN DEFAULT FALSE
    extseq.value.push(asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.BOOLEAN,
      false,
      String.fromCharCode(0xFF),
    ))
  }

  let value = ext.value
  if (typeof ext.value !== 'string') {
    // value is asn.1
    value = asn1.toDer(value).getBytes()
  }

  // extnValue (OCTET STRING)
  extseq.value.push(asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.OCTETSTRING,
    false,
    value,
  ))

  return extseq
}

/**
 * Converts a PKCS#10 certification request to an ASN.1 object.
 *
 * @param csr the certification request.
 *
 * @return the asn1 representation of a certification request.
 */
export function certificationRequestToAsn1(csr: CertificationRequest): any {
  // prefer cached CertificationRequestInfo over generating one
  const cri = csr.certificationRequestInfo || getCertificationRequestInfo(csr)

  // CertificationRequest
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // CertificationRequestInfo
    cri,
    // AlgorithmIdentifier (signature algorithm)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(csr.signatureOid).getBytes()),
      // parameters
      _signatureParametersToAsn1(csr.signatureOid, csr.signatureParameters),
    ]),
    // signature
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, String.fromCharCode(0x00) + csr.signature),
  ])
}

/**
 * Creates a CA store.
 *
 * @param certs an optional array of certificate objects or PEM-formatted
 *          certificate strings to add to the CA store.
 *
 * @return the CA store.
 */
export function createCaStore(certs): CAStore {
  // create CA store
  const caStore = {
    // stored certificates
    certs: {},
    getIssuer: function (cert) {
      const rval = getBySubject(cert.issuer)

      // see if there are multiple matches
      /* if(Array.isArray(rval)) {
        // TODO: resolve multiple matches by checking
        // authorityKey/subjectKey/issuerUniqueID/other identifiers, etc.
        // FIXME: or alternatively do authority key mapping
        // if possible (X.509v1 certs can't work?)
        throw new Error('Resolving multiple issuer matches not implemented yet.');
      } */

      return rval
    },
    addCertificate: function (cert) {
      // convert from pem if necessary
      if (typeof cert === 'string')
        cert = certificateFromPem(cert)

      ensureSubjectHasHash(cert.subject)

      if (!caStore.hasCertificate(cert)) { // avoid duplicate certificates in store
        if (cert.subject.hash in caStore.certs) {
          // subject hash already exists, append to array
          let tmp = caStore.certs[cert.subject.hash]
          if (!Array.isArray(tmp)) {
            tmp = [tmp]
          }
          tmp.push(cert)
          caStore.certs[cert.subject.hash] = tmp
        }
        else {
          caStore.certs[cert.subject.hash] = cert
        }
      }
    },
    hasCertificate: function (cert) {
      // convert from pem if necessary
      if (typeof cert === 'string') {
        cert = pki.certificateFromPem(cert)
      }

      let match = getBySubject(cert.subject)
      if (!match)
        return false

      if (!Array.isArray(match))
        match = [match]

      // compare DER-encoding of certificates
      const der1 = asn1.toDer(certificateToAsn1(cert)).getBytes()
      for (let i = 0; i < match.length; ++i) {
        const der2 = asn1.toDer(certificateToAsn1(match[i])).getBytes()
        if (der1 === der2)
          return true
      }

      return false
    },
    listAllCertificates: function () {
      const certList = []

      for (const hash in caStore.certs) {
        if (caStore.certs.hasOwnProperty(hash)) {
          const value = caStore.certs[hash]
          if (!Array.isArray(value)) {
            certList.push(value)
          }
          else {
            for (let i = 0; i < value.length; ++i) {
              certList.push(value[i])
            }
          }
        }
      }

      return certList
    },
    removeCertificate: function (cert) {
      let result

      // convert from pem if necessary
      if (typeof cert === 'string') {
        cert = certificateFromPem(cert)
      }
      ensureSubjectHasHash(cert.subject)
      if (!caStore.hasCertificate(cert)) {
        return null
      }

      const match = getBySubject(cert.subject)

      if (!Array.isArray(match)) {
        result = caStore.certs[cert.subject.hash]
        delete caStore.certs[cert.subject.hash]
        return result
      }

      // compare DER-encoding of certificates
      const der1 = asn1.toDer(pki.certificateToAsn1(cert)).getBytes()
      for (let i = 0; i < match.length; ++i) {
        const der2 = asn1.toDer(pki.certificateToAsn1(match[i])).getBytes()
        if (der1 === der2) {
          result = match[i]
          match.splice(i, 1)
        }
      }
      if (match.length === 0) {
        delete caStore.certs[cert.subject.hash]
      }

      return result
    },
  }

  function getBySubject(subject) {
    ensureSubjectHasHash(subject)
    return caStore.certs[subject.hash] || null
  }

  function ensureSubjectHasHash(subject) {
    // produce subject hash if it doesn't exist
    if (!subject.hash) {
      const md = md.sha1.create()
      subject.attributes = RDNAttributesAsArray(_dnToAsn1(subject), md)
      subject.hash = md.digest().toHex()
    }
  }

  // auto-add passed in certs
  if (certs) {
    // parse PEM-formatted certificates as necessary
    for (let i = 0; i < certs.length; ++i) {
      const cert = certs[i]
      caStore.addCertificate(cert)
    }
  }

  return caStore
}

/**
 * Certificate verification errors, based on TLS.
 */
export const certificateError = {
  bad_certificate: 'pki.BadCertificate',
  unsupported_certificate: 'pki.UnsupportedCertificate',
  certificate_revoked: 'pki.CertificateRevoked',
  certificate_expired: 'pki.CertificateExpired',
  certificate_unknown: 'pki.CertificateUnknown',
  unknown_ca: 'pki.UnknownCertificateAuthority',
} as const

/**
 * Verifies a certificate chain against the given Certificate Authority store
 * with an optional custom verify callback.
 *
 * @param caStore a certificate store to verify against.
 * @param chain the certificate chain to verify, with the root or highest authority at the end (an array of certificates).
 * @param options a callback to be called for every certificate in the chain or
 * @param options.verify a callback to be called for every certificate in the chain
 * @param options.validityCheckDate the date against which the certificate validity period should be checked. Pass null to not check the validity period. By default, the current date is used.
 *
 * The verify callback has the following signature:
 *
 * verified - Set to true if certificate was verified, otherwise the certificateError for why the certificate failed.
 * depth - The current index in the chain, where 0 is the end point's cert.
 * certs - The certificate chain, *NOTE* an empty chain indicates an anonymous end point.
 *
 * The function returns true on success and on failure either the appropriate
 * certificateError or an object with 'error' set to the appropriate
 * certificateError and 'message' set to a custom error message.
 *
 * @return true if successful, error thrown if not.
 */
export function verifyCertificateChain(
  caStore: CAStore,
  chain: Certificate[],
  options: {
    verify?: (cert: Certificate, index: number, chain: Certificate[]) => boolean | CustomError
    validityCheckDate?: Date
  } = {}
): boolean {
  /* From: RFC3280 - Internet X.509 Public Key Infrastructure Certificate
    Section 6: Certification Path Validation
    See inline parentheticals related to this particular implementation. */

  // copy cert chain references to another array to protect against changes
  // in verify callback
  chain = chain.slice(0)
  let validityCheckDate = options.validityCheckDate || new Date()

  // check each cert in chain using its parent, where parent is either
  // the next in the chain or from the CA store
  let first = true
  let error: CustomError | null = null
  let depth = 0
  do {
    let cert = chain.shift()
    let parent: Certificate | null = null
    let selfSigned = false

    // 1. verify validity period
    if (validityCheckDate < cert.validity.notBefore || validityCheckDate > cert.validity.notAfter) {
      error = {
        message: 'Certificate is not valid yet or has expired.',
        error: 'pki.CertificateExpired',
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
        now: validityCheckDate,
      }
    }

    // 2. verify not revoked (todo)

    // 3. verify cert signature
    if (error === null) {
      parent = chain[0] || caStore.getIssuer(cert)
      if (parent === null) {
        // check if cert is self-signed
        if (cert.isIssuer(cert)) {
          selfSigned = true
          parent = cert
        }
      }

      if (parent) {
        // verify parent signature on cert
        try {
          if (!parent.verify(cert)) {
            error = {
              message: 'Certificate signature is invalid.',
              error: 'pki.BadCertificate',
            }
          }
        }
        catch (ex) {
          error = {
            message: 'Certificate signature is invalid.',
            error: 'pki.BadCertificate',
            details: ex.toString(),
          }
        }
      }

      if (error === null && (!parent || selfSigned) && !caStore.hasCertificate(cert)) {
        error = {
          message: 'Certificate is not trusted.',
          error: 'pki.UnknownCertificateAuthority',
        }
      }
    }

    // 4. verify certificate extensions
    if (error === null && !first && cert.extensions) {
      // verify certificate basic constraints
      const bcExt = cert.getExtension('basicConstraints')
      if (bcExt) {
        if (!bcExt.cA) {
          error = {
            message:
              'Certificate keyUsage or basicConstraints conflict or indicate certificate is not a CA. ' +
              'Certificate cannot be used for certification.',
            error: 'pki.BadCertificate',
          }
        }
        else if ('pathLenConstraint' in bcExt && bcExt.pathLenConstraint >= 0) {
          if (depth > bcExt.pathLenConstraint) {
            error = {
              message: 'Certificate path is too long; path length constraint violated.',
              error: 'pki.BadCertificate',
            }
          }
        }
      }
    }

    // call application callback
    if (error === null && options.verify) {
      const ret = options.verify(cert, depth, chain)
      if (ret === false) {
        error = {
          message: 'The application rejected the certificate.',
          error: 'pki.BadCertificate',
        }
      }
      else if (typeof ret === 'object' && !Array.isArray(ret)) {
        if (ret.message)
          error = ret
        if (ret.error)
          error = ret
      }
      else if (typeof ret === 'string') {
        error = {
          message: 'The application rejected the certificate.',
          error: ret,
        }
      }
    }

    // no longer first cert in chain
    first = false
    ++depth
  } while (error === null && chain.length > 0)

  if (error !== null)
    throw error

  return true
}

function _containsAll(iattr: RDNAttribute[], sattr: RDNAttribute[]): boolean {
  // ensure all parent subject attributes are present in issuer
  let rval = true
  for (let i = 0; rval && i < sattr.length; ++i) {
    const attr = sattr[i]
    rval = false
    for (let j = 0; !rval && j < iattr.length; ++j) {
      if (attr.type === iattr[j].type && attr.value === iattr[j].value) {
        rval = true
      }
    }
  }
  return rval
}

function _getAttribute(obj: any, sn: string): RDNAttribute | null {
  if (sn in _shortNames) {
    sn = _shortNames[sn]
  }
  const rval = obj.attributes.filter((attr: RDNAttribute) => attr.shortName === sn)
  return rval.length > 0 ? rval[0] : null
}

function _fillMissingFields(attrs: RDNAttribute[]): void {
  for (const attr of attrs) {
    // populate missing name
    if (typeof attr.name === 'undefined') {
      if (attr.type && attr.type in oids) {
        attr.name = oids[attr.type]
      }
      else if (attr.shortName && attr.shortName in _shortNames) {
        attr.name = oids[_shortNames[attr.shortName]]
      }
    }

    // populate missing type (OID)
    if (typeof attr.type === 'undefined') {
      if (attr.name && attr.name in oids) {
        attr.type = oids[attr.name]
      }
      else {
        const error = new Error('Attribute type not specified.')
        error.attribute = attr
        throw error
      }
    }

    // populate missing shortName
    if (typeof attr.shortName === 'undefined') {
      if (attr.name && attr.name in _shortNames) {
        attr.shortName = _shortNames[attr.name]
      }
    }

    // convert extensions to value
    if (attr.type === oids.extensionRequest && attr.extensions) {
      attr.valueTagClass = asn1.Type.SEQUENCE
      attr.valueConstructed = true
      attr.value = []
      for (const ext of attr.extensions) {
        attr.value.push(certificateExtensionToAsn1(_fillMissingExtensionFields(ext)))
      }
    }

    if (typeof attr.value === 'undefined') {
      const error = new Error('Attribute value not specified.')
      error.attribute = attr
      throw error
    }
  }
}

function _fillMissingExtensionFields(e: CertificateExtension, options: any = {}): CertificateExtension {
  // populate missing name
  if (typeof e.name === 'undefined') {
    if (e.id && e.id in oids) {
      e.name = oids[e.id]
    }
  }

  // populate missing id
  if (typeof e.id === 'undefined') {
    if (e.name && e.name in oids) {
      e.id = oids[e.name]
    }
    else {
      const error = new Error('Extension ID not specified.')
      error.extension = e
      throw error
    }
  }

  // handle value
  if (typeof e.value !== 'undefined') {
    // TODO: validate value
  }
  else {
    const error = new Error('Extension value not specified.')
    error.extension = e
    throw error
  }

  return e
}

function _createSignatureDigest(options: {
  signatureOid: string
  type: string
}): IMessageDigest {
  switch (options.signatureOid) {
    case oids.sha1WithRSAEncryption:
      return md.sha1.create()
    case oids.sha256WithRSAEncryption:
      return md.sha256.create()
    case oids.sha384WithRSAEncryption:
      return md.sha384.create()
    case oids.sha512WithRSAEncryption:
      return md.sha512.create()
    case oids['RSASSA-PSS']:
      return md.sha256.create()
    default:
      throw {
        message: `Could not compute ${options.type} digest. Unknown signature OID.`,
        error: 'pki.BadCertificate',
        signatureOid: options.signatureOid
      } as CustomError
  }
}

// Add this interface near the top with other interfaces
interface AltName {
  type: number
  value: any
  ip?: string | null
  oid?: string
}
