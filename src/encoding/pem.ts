/**
 * TypeScript implementation of basic PEM (Privacy Enhanced Mail) algorithms.
 *
 * See: RFC 1421.
 *
 * @author Dave Longley
 * @author Chris Breuer
 *
 * A PEM object has the following fields:
 *
 * type: identifies the type of message (eg: "RSA PRIVATE KEY").
 *
 * procType: identifies the type of processing performed on the message,
 *   it has two subfields: version and type, eg: 4,ENCRYPTED.
 *
 * contentDomain: identifies the type of content in the message, typically
 *   only uses the value: "RFC822".
 *
 * dekInfo: identifies the message encryption algorithm and mode and includes
 *   any parameters for the algorithm, it has two subfields: algorithm and
 *   parameters, eg: DES-CBC,F8143EDE5960C597.
 *
 * headers: contains all other PEM encapsulated headers -- where order is
 *   significant (for pairing data like recipient ID + key info).
 *
 * body: the binary-encoded body.
 */
import { decode64, encode64 } from './utils'

export interface ProcType {
  version: string
  type: string
}

export interface DekInfo {
  algorithm: string
  parameters: string | null
}

export interface PemHeader {
  name: string
  values: string[]
}

export interface PemMessage {
  type: string
  procType: ProcType | null
  contentDomain: string | null
  dekInfo: DekInfo | null
  headers: PemHeader[]
  body: string
}

export interface PemOptions {
  maxline?: number
}

/**
 * Encodes (serializes) the given PEM object.
 *
 * @param msg the PEM message object to encode.
 * @param options the options to use:
 *          maxline the maximum characters per line for the body, (default: 64).
 *
 * @return the PEM-formatted string.
 */
export function encode(msg: PemMessage, options: PemOptions = {}): string {
  let rval = `-----BEGIN ${msg.type}-----\r\n`

  // encode special headers
  let header: PemHeader
  if (msg.procType) {
    header = {
      name: 'Proc-Type',
      values: [String(msg.procType.version), msg.procType.type],
    }
    rval += foldHeader(header)
  }
  if (msg.contentDomain) {
    header = { name: 'Content-Domain', values: [msg.contentDomain] }
    rval += foldHeader(header)
  }
  if (msg.dekInfo) {
    header = { name: 'DEK-Info', values: [msg.dekInfo.algorithm] }
    if (msg.dekInfo.parameters) {
      header.values.push(msg.dekInfo.parameters)
    }
    rval += foldHeader(header)
  }

  if (msg.headers) {
    // encode all other headers
    for (let i = 0; i < msg.headers.length; ++i) {
      rval += foldHeader(msg.headers[i])
    }
  }

  // terminate header
  if (msg.procType) {
    rval += '\r\n'
  }

  // add body
  rval += `${encode64(msg.body, options.maxline || 64)}\r\n`

  rval += `-----END ${msg.type}-----\r\n`

  return rval
}

/**
 * Decodes (deserializes) all PEM messages found in the given string.
 *
 * @param str the PEM-formatted string to decode.
 *
 * @return the PEM message objects in an array.
 */
export function decode(str: string): PemMessage[] {
  const rval: PemMessage[] = []

  // split string into PEM messages (be lenient w/EOF on BEGIN line)
  const rMessage = /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7E\s]+?\r?\n\r?\n)?([:A-Za-z0-9+/=\s]+)-----END \1-----/g
  const rHeader = /([\x21-\x7E]+):\s*([\x21-\x7E\s]+)/
  const rCRLF = /\r?\n/
  let match: RegExpExecArray | null
  while (true) {
    match = rMessage.exec(str)
    if (!match)
      break

    // accept "NEW CERTIFICATE REQUEST" as "CERTIFICATE REQUEST"
    let type = match[1]
    if (type === 'NEW CERTIFICATE REQUEST')
      type = 'CERTIFICATE REQUEST'

    const msg: PemMessage = {
      type,
      procType: null,
      contentDomain: null,
      dekInfo: null,
      headers: [],
      body: decode64(match[3]),
    }
    rval.push(msg)

    // no headers
    if (!match[2])
      continue

    // parse headers
    const lines = match[2].split(rCRLF)
    let li = 0
    while (match && li < lines.length) {
      // get line, trim any rhs whitespace
      let line = lines[li].replace(/\s+$/, '')

      // RFC2822 unfold any following folded lines
      for (let nl = li + 1; nl < lines.length; ++nl) {
        const next = lines[nl]
        if (!/\s/.test(next[0]))
          break
        line += next
        li = nl
      }

      // parse header
      const headerMatch = line.match(rHeader)
      if (headerMatch) {
        const header: PemHeader = { name: headerMatch[1], values: [] }
        const values = headerMatch[2].split(',')
        for (let vi = 0; vi < values.length; ++vi) {
          header.values.push(ltrim(values[vi]))
        }

        // Proc-Type must be the first header
        if (!msg.procType) {
          if (header.name !== 'Proc-Type') {
            throw new Error('Invalid PEM formatted message. The first '
              + 'encapsulated header must be "Proc-Type".')
          }
          else if (header.values.length !== 2) {
            throw new Error('Invalid PEM formatted message. The "Proc-Type" '
              + 'header must have two subfields.')
          }
          msg.procType = { version: values[0], type: values[1] }
        }
        else if (!msg.contentDomain && header.name === 'Content-Domain') {
          // special-case Content-Domain
          msg.contentDomain = values[0] || ''
        }
        else if (!msg.dekInfo && header.name === 'DEK-Info') {
          // special-case DEK-Info
          if (header.values.length === 0) {
            throw new Error('Invalid PEM formatted message. The "DEK-Info" '
              + 'header must have at least one subfield.')
          }
          msg.dekInfo = { algorithm: values[0], parameters: values[1] || null }
        }
        else {
          msg.headers.push(header)
        }
      }
      ++li
    }

    if (msg.procType?.type === 'ENCRYPTED' && !msg.dekInfo) {
      throw new Error('Invalid PEM formatted message. The "DEK-Info" '
        + 'header must be present if "Proc-Type" is "ENCRYPTED".')
    }
  }

  if (rval.length === 0) {
    throw new Error('Invalid PEM formatted message.')
  }

  return rval
}

function foldHeader(header: PemHeader): string {
  let rval = `${header.name}: `

  // ensure values with CRLF are folded
  const values: string[] = []
  const insertSpace = function (_match: string, $1: string): string {
    return ` ${$1}`
  }

  for (let i = 0; i < header.values.length; ++i) {
    values.push(header.values[i].replace(/^(\S+\r\n)/, insertSpace))
  }

  rval += `${values.join(',')}\r\n`

  // do folding
  let length = 0
  let candidate = -1

  for (let i = 0; i < rval.length; ++i, ++length) {
    if (length > 65 && candidate !== -1) {
      const insert = rval[candidate]
      if (insert === ',') {
        ++candidate
        rval = `${rval.substr(0, candidate)}\r\n ${rval.substr(candidate)}`
      }
      else {
        rval = `${rval.substr(0, candidate)}\r\n${insert}${rval.substr(candidate + 1)}`
      }
      length = (i - candidate - 1)
      candidate = -1
      ++i
    }
    else if (rval[i] === ' ' || rval[i] === '\t' || rval[i] === ',') {
      candidate = i
    }
  }

  return rval
}

function ltrim(str: string): string {
  return str.replace(/^\s+/, '')
}

export interface Pem {
  encode: (msg: PemMessage, options?: PemOptions) => string
  decode: (str: string) => PemMessage[]
}

export const pem: Pem = {
  encode,
  decode,
}

export default pem
