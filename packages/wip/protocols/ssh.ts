/**
 * Functions to output keys in SSH-friendly formats.
 *
 * This is part of the Forge project which may be used under the terms of
 * either the BSD License or the GNU General Public License (GPL) Version 2.
 *
 * See: https://github.com/digitalbazaar/forge/blob/cbebca3780658703d925b61b2caffb1d263a6c1d/LICENSE
 *
 * @author https://github.com/shellac
 */

import { md5 } from '../algorithms/hash/md5'
import { sha1 } from '../algorithms/hash/sha1'
import { createCipher } from '../algorithms/symmetric/cipher'
import { encryptRsaPrivateKey, privateKeyToPem } from '../pki'
import util, { createBuffer, encode64 } from '../utils'
import { create as hmacCreate } from '../utils/hmac'

/**
 * Encodes (and optionally encrypts) a private RSA key as a Putty PPK file.
 *
 * @param privateKey the key.
 * @param passphrase a passphrase to protect the key (falsy for no encryption).
 * @param comment a comment to include in the key file.
 *
 * @return the PPK file as a string.
 */
function privateKeyToPutty(privateKey: any, passphrase: any, comment: any) {
  comment = comment || ''
  passphrase = passphrase || ''
  const algorithm = 'ssh-rsa'
  const encryptionAlgorithm = (passphrase === '') ? 'none' : 'aes256-cbc'

  let ppk = `PuTTY-User-Key-File-2: ${algorithm}\r\n`
  ppk += `Encryption: ${encryptionAlgorithm}\r\n`
  ppk += `Comment: ${comment}\r\n`

  // public key into buffer for ppk
  const pubbuffer = createBuffer()
  _addStringToBuffer(pubbuffer, algorithm)
  _addBigIntegerToBuffer(pubbuffer, privateKey.e)
  _addBigIntegerToBuffer(pubbuffer, privateKey.n)

  // write public key
  const pub = encode64(pubbuffer.bytes(), 64)
  let length = Math.floor(pub.length / 66) + 1 // 66 = 64 + \r\n
  ppk += `Public-Lines: ${length}\r\n`
  ppk += pub

  // private key into a buffer
  const privbuffer = createBuffer()
  _addBigIntegerToBuffer(privbuffer, privateKey.d)
  _addBigIntegerToBuffer(privbuffer, privateKey.p)
  _addBigIntegerToBuffer(privbuffer, privateKey.q)
  _addBigIntegerToBuffer(privbuffer, privateKey.qInv)

  // optionally encrypt the private key
  let priv
  if (!passphrase) {
    // use the unencrypted buffer
    priv = encode64(privbuffer.bytes(), 64)
  }
  else {
    // encrypt RSA key using passphrase
    let encLen = privbuffer.length() + 16 - 1
    encLen -= encLen % 16

    // pad private key with sha1-d data -- needs to be a multiple of 16
    const padding = _sha1(privbuffer.bytes())

    padding.truncate(padding.length() - encLen + privbuffer.length())
    privbuffer.putBuffer(padding)

    const aeskey = createBuffer()
    aeskey.putBuffer(_sha1('\x00\x00\x00\x00', passphrase))
    aeskey.putBuffer(_sha1('\x00\x00\x00\x01', passphrase))

    // encrypt some bytes using CBC mode
    // key is 40 bytes, so truncate *by* 8 bytes
    const cipher = createCipher('AES-CBC', aeskey.truncate(8).bytes())
    cipher.start({ iv: createBuffer().fillWithByte(0, 16) })
    cipher.update(privbuffer.copy())
    cipher.finish()
    const encrypted = cipher.output

    // Note: this appears to differ from Putty -- is forge wrong, or putty?
    // due to padding we finish as an exact multiple of 16
    encrypted?.truncate(16) // all padding

    priv = encode64(encrypted?.bytes() || '', 64)
  }

  // output private key
  length = Math.floor(priv.length / 66) + 1 // 64 + \r\n
  ppk += `\r\nPrivate-Lines: ${length}\r\n`
  ppk += priv

  // MAC
  const mackey = _sha1('putty-private-key-file-mac-key', passphrase)

  const macbuffer = createBuffer()
  _addStringToBuffer(macbuffer, algorithm)
  _addStringToBuffer(macbuffer, encryptionAlgorithm)
  _addStringToBuffer(macbuffer, comment)
  macbuffer.putInt32(pubbuffer.length())
  macbuffer.putBuffer(pubbuffer)
  macbuffer.putInt32(privbuffer.length())
  macbuffer.putBuffer(privbuffer)

  const hmac = hmacCreate()
  hmac.start('sha1', mackey)
  hmac.update(macbuffer.bytes())

  ppk += `\r\nPrivate-MAC: ${hmac.digest().toHex()}\r\n`

  return ppk
}

/**
 * Encodes a public RSA key as an OpenSSH file.
 *
 * @param key the key.
 * @param comment a comment.
 *
 * @return the public key in OpenSSH format.
 */
export function publicKeyToOpenSSH(key: any, comment: any) {
  const type = 'ssh-rsa'
  comment = comment || ''

  const buffer = createBuffer()
  _addStringToBuffer(buffer, type)
  _addBigIntegerToBuffer(buffer, key.e)
  _addBigIntegerToBuffer(buffer, key.n)

  return `${type} ${encode64(buffer.bytes())} ${comment}`
}

/**
 * Encodes a private RSA key as an OpenSSH file.
 *
 * @param key the key.
 * @param passphrase a passphrase to protect the key (falsy for no encryption).
 *
 * @return the public key in OpenSSH format.
 */
export function privateKeyToOpenSSH(privateKey: any, passphrase: any): string {
  if (!passphrase)
    return privateKeyToPem(privateKey)

  // OpenSSH private key is just a legacy format, it seems
  return encryptRsaPrivateKey(privateKey, passphrase, { legacy: true, algorithm: 'aes128' })
}

/**
 * Gets the SSH fingerprint for the given public key.
 *
 * @param options the options to use.
 *          [md] the message digest object to use (defaults to forge.md.md5).
 *          [encoding] an alternative output encoding, such as 'hex'
 *            (defaults to none, outputs a byte buffer).
 *          [delimiter] the delimiter to use between bytes for 'hex' encoded
 *            output, eg: ':' (defaults to none).
 *
 * @return the fingerprint as a byte buffer or other encoding based on options.
 */
export function getPublicKeyFingerprint(key: any, options: any): string | Buffer {
  options = options || {}
  const md = options.md || md5.create()

  const type = 'ssh-rsa'
  const buffer = createBuffer()
  _addStringToBuffer(buffer, type)
  _addBigIntegerToBuffer(buffer, key.e)
  _addBigIntegerToBuffer(buffer, key.n)

  // hash public key bytes
  md.start()
  md.update(buffer.getBytes())
  const digest = md.digest()
  if (options.encoding === 'hex') {
    const hex = digest.toHex()

    if (options.delimiter)
      return hex.match(/.{2}/g).join(options.delimiter)

    return hex
  }
  else if (options.encoding === 'binary') {
    return digest.getBytes()
  }
  else if (options.encoding) {
    throw new Error(`Unknown encoding "${options.encoding}".`)
  }
  return digest
}

/**
 * Adds len(val) then val to a buffer.
 *
 * @param buffer the buffer to add to.
 * @param val a big integer.
 */
function _addBigIntegerToBuffer(buffer: any, val: any) {
  let hexVal = val.toString(16)
  // ensure 2s complement +ve
  if (hexVal[0] >= '8') {
    hexVal = `00${hexVal}`
  }
  const bytes = util.hexToBytes(hexVal)
  buffer.putInt32(bytes.length)
  buffer.putBytes(bytes)
}

/**
 * Adds len(val) then val to a buffer.
 *
 * @param buffer the buffer to add to.
 * @param val a string.
 */
function _addStringToBuffer(buffer, val) {
  buffer.putInt32(val.length)
  buffer.putString(val)
}

/**
 * Hashes the arguments into one value using SHA-1.
 *
 * @return the sha1 hash of the provided arguments.
 */
function _sha1() {
  const sha = sha1.create()
  const num = arguments.length
  for (let i = 0; i < num; ++i) {
    sha.update(arguments[i])
  }
  return sha.digest()
}
