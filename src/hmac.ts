/**
 * Hash-based Message Authentication Code implementation. Requires a message
 * digest object that can be obtained, for example, from forge.md.sha1 or
 * forge.md.md5.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2012 Digital Bazaar, Inc. All rights reserved.
 */

import { ByteStringBuffer, createBuffer } from "./utils"

type MessageDigest = {
  start: () => MessageDigest
  update: (msg: string | ByteStringBuffer, encoding?: string) => MessageDigest
  digest: () => ByteStringBuffer
  blockLength: number
}

type NativeBuffer = Buffer | Uint8Array | ArrayBuffer

type HMACInput = string | ByteStringBuffer | NativeBuffer

interface HMAC {
  start: (md: MessageDigest, key: HMACInput) => void
  update: (bytes: HMACInput) => void
  getMac: () => ByteStringBuffer
  digest: () => ByteStringBuffer
}

interface HMACModule {
  create: () => HMAC
}

/**
 * Creates an HMAC object that uses the given message digest object.
 *
 * @return an HMAC object.
 */
function create(): HMAC {
  // the hmac key to use
  let _key: ByteStringBuffer | null = null

  // the message digest to use
  let _md: MessageDigest | null = null

  // the inner padding
  let _ipadding: string | null = null

  // the outer padding
  let _opadding: string | null = null

  // hmac context
  const ctx: HMAC = {
    start: (md: MessageDigest, key: HMACInput) => {
      if (!md) {
        throw new TypeError('"md" argument is required')
      }

      _md = md

      if (key === null) {
        if (!_key) {
          throw new TypeError('Key is required for first call to start()')
        }
        key = _key
      }

      // convert key to ByteStringBuffer
      let keyBuffer: ByteStringBuffer
      if (typeof key === 'string') {
        keyBuffer = createBuffer(key)
      }
      else if (key instanceof ByteStringBuffer) {
        keyBuffer = key
      }
      else if (key instanceof Uint8Array || key instanceof Buffer || key instanceof ArrayBuffer) {
        keyBuffer = createBuffer()
        const view = key instanceof ArrayBuffer ? new Uint8Array(key) : key
        for (let i = 0; i < view.length; ++i) {
          keyBuffer.putByte(view[i])
        }
      }
      else {
        throw new TypeError(
          '"key" must be a string, ByteStringBuffer, Buffer, Uint8Array, or ArrayBuffer',
        )
      }

      // if key is longer than blocksize, hash it
      let keylen = keyBuffer.length()
      if (keylen > _md.blockLength) {
        _md.start()
        _md.update(keyBuffer)
        keyBuffer = _md.digest()
      }

      // mix key into inner and outer padding
      // ipadding = [0x36 * blocksize] ^ key
      // opadding = [0x5C * blocksize] ^ key
      const ipadding = createBuffer()
      const opadding = createBuffer()
      keylen = keyBuffer.length()

      for (let i = 0; i < keylen; ++i) {
        const tmp = keyBuffer.at(i)
        ipadding.putByte(0x36 ^ tmp)
        opadding.putByte(0x5C ^ tmp)
      }

      // if key is shorter than blocksize, add additional padding
      if (keylen < _md.blockLength) {
        const remaining = _md.blockLength - keylen
        for (let i = 0; i < remaining; ++i) {
          ipadding.putByte(0x36)
          opadding.putByte(0x5C)
        }
      }

      _key = keyBuffer
      _ipadding = ipadding.bytes()
      _opadding = opadding.bytes()

      // digest is done like so: hash(opadding | hash(ipadding | message))
      // prepare to do inner hash
      // hash(ipadding | message)
      _md.start()
      _md.update(_ipadding)
    },

    update: (bytes: HMACInput) => {
      if (!_md) {
        throw new Error('HMAC not started. Call start() first.')
      }

      // convert bytes to ByteStringBuffer if needed
      if (bytes instanceof ByteStringBuffer || typeof bytes === 'string') {
        _md.update(bytes)
      }
      else {
        const buffer = createBuffer()
        const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes
        for (let i = 0; i < view.length; ++i) {
          buffer.putByte(view[i])
        }
        _md.update(buffer.bytes())
      }
    },

    getMac: () => {
      if (!_md || !_opadding) {
        throw new Error('HMAC not started. Call start() first.')
      }

      // digest is done like so: hash(opadding | hash(ipadding | message))
      // here we do the outer hashing
      const inner = _md.digest().bytes()
      _md.start()
      _md.update(_opadding)
      _md.update(inner)
      return _md.digest()
    },

    digest() {
      return this.getMac()
    }
  }

  return ctx
}

// Export the HMAC implementation
export const hmac: HMACModule = {
  create,
}
