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
  ans1PrivateKeyValidator: Asn1Validator
  ans1PublicKeyValidator: Asn1Validator
}
