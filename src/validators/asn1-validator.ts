import { Class, Type } from './asn1'

export interface Asn1Validator {
  name: string
  tagClass: number
  type: number
  constructed: boolean
  value: Asn1Validator[]
  capture?: string
  captureAsn1?: string
  captureBitStringContents?: string
  captureBitStringValue?: string
  optional?: boolean
  composed?: boolean
}

export interface ValidatorMap {
  privateKeyValidator: Asn1Validator
  publicKeyValidator: Asn1Validator
}

export const privateKeyValidator: Asn1Validator = {
  // PrivateKeyInfo
  name: 'PrivateKeyInfo',
  tagClass: Class.UNIVERSAL,
  type: Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'PrivateKeyInfo.version',
    tagClass: Class.UNIVERSAL,
    type: Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion',
    value: [],
  }, {
    // privateKeyAlgorithm
    name: 'PrivateKeyInfo.privateKeyAlgorithm',
    tagClass: Class.UNIVERSAL,
    type: Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: Class.UNIVERSAL,
      type: Type.OID,
      constructed: false,
      capture: 'privateKeyOid',
      value: [],
    }],
  }, {
    // PrivateKey
    name: 'PrivateKeyInfo',
    tagClass: Class.UNIVERSAL,
    type: Type.OCTETSTRING,
    constructed: false,
    capture: 'privateKey',
    value: [],
  }],
}

export const publicKeyValidator: Asn1Validator = {
  name: 'SubjectPublicKeyInfo',
  tagClass: Class.UNIVERSAL,
  type: Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'subjectPublicKeyInfo',
  value: [{
    name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
    tagClass: Class.UNIVERSAL,
    type: Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: Class.UNIVERSAL,
      type: Type.OID,
      constructed: false,
      capture: 'publicKeyOid',
      value: [],
    }],
  },
  // capture group for ed25519PublicKey
  {
    name: 'SubjectPublicKeyInfo.subjectPublicKey',
    tagClass: Class.UNIVERSAL,
    type: Type.BITSTRING,
    constructed: false,
    composed: true,
    captureBitStringValue: 'ed25519PublicKey',
    value: [],
  }],
}

export const asn1Validator: ValidatorMap = {
  privateKeyValidator,
  publicKeyValidator,
}

export default asn1Validator
