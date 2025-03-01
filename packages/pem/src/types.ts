/**
 * TypeScript types for PEM (Privacy Enhanced Mail) implementation.
 */

/**
 * Represents a PEM header with a name and array of values.
 */
export interface PEMHeader {
  name: string
  values: string[]
}

/**
 * Represents the processing type information in a PEM message.
 */
export interface ProcType {
  version: string
  type: string
}

/**
 * Represents the Data Encryption Key information in a PEM message.
 */
export interface DEKInfo {
  algorithm: string
  parameters: string | null
}

/**
 * Represents a decoded PEM message.
 */
export interface PEMMessage {
  type: string
  procType: ProcType | null
  contentDomain: string | null
  dekInfo: DEKInfo | null
  headers: PEMHeader[]
  body: Uint8Array
}

/**
 * Options for encoding PEM messages.
 */
export interface PEMEncodeOptions {
  maxline?: number
}
