import { asn1 } from '../encoding/asn1'
import { pki } from '../pki'
// @ts-nocheck
/**
 * A TypeScript implementation of Transport Layer Security (TLS).
 *
 * @author Dave Longley
 * @author Chris Breuer
 *
 * The TLS Handshake Protocol involves the following steps:
 *
 * - Exchange hello messages to agree on algorithms, exchange random values,
 * and check for session resumption.
 *
 * - Exchange the necessary cryptographic parameters to allow the client and
 * server to agree on a premaster secret.
 *
 * - Exchange certificates and cryptographic information to allow the client
 * and server to authenticate themselves.
 *
 * - Generate a master secret from the premaster secret and exchanged random values.
 *
 * - Provide security parameters to the record layer.
 *
 * - Allow the client and server to verify that their peer has calculated the
 * same security parameters and that the handshake occurred without tampering
 * by an attacker.
 *
 * Up to 4 different messages may be sent during a key exchange. The server
 * certificate, the server key exchange, the client certificate, and the
 * client key exchange.
 *
 * A typical handshake (from the client's perspective).
 *
 * 1. Client sends ClientHello.
 * 2. Client receives ServerHello.
 * 3. Client receives optional Certificate.
 * 4. Client receives optional ServerKeyExchange.
 * 5. Client receives ServerHelloDone.
 * 6. Client sends optional Certificate.
 * 7. Client sends ClientKeyExchange.
 * 8. Client sends optional CertificateVerify.
 * 9. Client sends ChangeCipherSpec.
 * 10. Client sends Finished.
 * 11. Client receives ChangeCipherSpec.
 * 12. Client receives Finished.
 * 13. Client sends/receives application data.
 *
 * To reuse an existing session:
 *
 * 1. Client sends ClientHello with session ID for reuse.
 * 2. Client receives ServerHello with same session ID if reusing.
 * 3. Client receives ChangeCipherSpec message if reusing.
 * 4. Client receives Finished.
 * 5. Client sends ChangeCipherSpec.
 * 6. Client sends Finished.
 *
 * Note: Client ignores HelloRequest if in the middle of a handshake.
 *
 * Record Layer:
 *
 * The record layer fragments information blocks into TLSPlaintext records
 * carrying data in chunks of 2^14 bytes or less. Client message boundaries are
 * not preserved in the record layer (i.e., multiple client messages of the
 * same ContentType MAY be coalesced into a single TLSPlaintext record, or a
 * single message MAY be fragmented across several records).
 *
 * struct {
 *   uint8 major;
 *   uint8 minor;
 * } ProtocolVersion;
 *
 * struct {
 *   ContentType type;
 *   ProtocolVersion version;
 *   uint16 length;
 *   opaque fragment[TLSPlaintext.length];
 * } TLSPlaintext;
 *
 * type:
 *   The higher-level protocol used to process the enclosed fragment.
 *
 * version:
 *   The version of the protocol being employed. TLS Version 1.2 uses version
 *   {3, 3}. TLS Version 1.0 uses version {3, 1}. Note that a client that
 *   supports multiple versions of TLS may not know what version will be
 *   employed before it receives the ServerHello.
 *
 * length:
 *   The length (in bytes) of the following TLSPlaintext.fragment. The length
 *   MUST NOT exceed 2^14 = 16384 bytes.
 *
 * fragment:
 *   The application data. This data is transparent and treated as an
 *   independent block to be dealt with by the higher-level protocol specified
 *   by the type field.
 *
 * Implementations MUST NOT send zero-length fragments of Handshake, Alert, or
 * ChangeCipherSpec content types. Zero-length fragments of Application data
 * MAY be sent as they are potentially useful as a traffic analysis
 * countermeasure.
 *
 * Note: Data of different TLS record layer content types MAY be interleaved.
 * Application data is generally of lower precedence for transmission than
 * other content types. However, records MUST be delivered to the network in
 * the same order as they are protected by the record layer. Recipients MUST
 * receive and process interleaved application layer traffic during handshakes
 * subsequent to the first one on a connection.
 *
 * struct {
 *   ContentType type;       // same as TLSPlaintext.type
 *   ProtocolVersion version;// same as TLSPlaintext.version
 *   uint16 length;
 *   opaque fragment[TLSCompressed.length];
 * } TLSCompressed;
 *
 * length:
 *   The length (in bytes) of the following TLSCompressed.fragment.
 *   The length MUST NOT exceed 2^14 + 1024.
 *
 * fragment:
 *   The compressed form of TLSPlaintext.fragment.
 *
 * Note: A CompressionMethod.null operation is an identity operation; no fields
 * are altered. In this implementation, since no compression is supported,
 * uncompressed records are always the same as compressed records.
 *
 * Encryption Information:
 *
 * The encryption and MAC functions translate a TLSCompressed structure into a
 * TLSCiphertext. The decryption functions reverse the process. The MAC of the
 * record also includes a sequence number so that missing, extra, or repeated
 * messages are detectable.
 *
 * struct {
 *   ContentType type;
 *   ProtocolVersion version;
 *   uint16 length;
 *   select (SecurityParameters.cipher_type) {
 *     case stream: GenericStreamCipher;
 *     case block:  GenericBlockCipher;
 *     case aead:   GenericAEADCipher;
 *   } fragment;
 * } TLSCiphertext;
 *
 * type:
 *   The type field is identical to TLSCompressed.type.
 *
 * version:
 *   The version field is identical to TLSCompressed.version.
 *
 * length:
 *   The length (in bytes) of the following TLSCiphertext.fragment.
 *   The length MUST NOT exceed 2^14 + 2048.
 *
 * fragment:
 *   The encrypted form of TLSCompressed.fragment, with the MAC.
 *
 * Note: Only CBC Block Ciphers are supported by this implementation.
 *
 * The TLSCompressed.fragment structures are converted to/from block
 * TLSCiphertext.fragment structures.
 *
 * struct {
 *   opaque IV[SecurityParameters.record_iv_length];
 *   block-ciphered struct {
 *     opaque content[TLSCompressed.length];
 *     opaque MAC[SecurityParameters.mac_length];
 *     uint8 padding[GenericBlockCipher.padding_length];
 *     uint8 padding_length;
 *   };
 * } GenericBlockCipher;
 *
 * The MAC is generated as described in Section 6.2.3.1.
 *
 * IV:
 *   The Initialization Vector (IV) SHOULD be chosen at random, and MUST be
 *   unpredictable. Note that in versions of TLS prior to 1.1, there was no
 *   IV field, and the last ciphertext block of the previous record (the "CBC
 *   residue") was used as the IV. This was changed to prevent the attacks
 *   described in [CBCATT]. For block ciphers, the IV length is of length
 *   SecurityParameters.record_iv_length, which is equal to the
 *   SecurityParameters.block_size.
 *
 * padding:
 *   Padding that is added to force the length of the plaintext to be an
 *   integral multiple of the block cipher's block length. The padding MAY be
 *   any length up to 255 bytes, as long as it results in the
 *   TLSCiphertext.length being an integral multiple of the block length.
 *   Lengths longer than necessary might be desirable to frustrate attacks on
 *   a protocol that are based on analysis of the lengths of exchanged
 *   messages. Each uint8 in the padding data vector MUST be filled with the
 *   padding length value. The receiver MUST check this padding and MUST use
 *   the bad_record_mac alert to indicate padding errors.
 *
 * padding_length:
 *   The padding length MUST be such that the total size of the
 *   GenericBlockCipher structure is a multiple of the cipher's block length.
 *   Legal values range from zero to 255, inclusive. This length specifies the
 *   length of the padding field exclusive of the padding_length field itself.
 *
 * The encrypted data length (TLSCiphertext.length) is one more than the sum of
 * SecurityParameters.block_length, TLSCompressed.length,
 * SecurityParameters.mac_length, and padding_length.
 *
 * Example: If the block length is 8 bytes, the content length
 * (TLSCompressed.length) is 61 bytes, and the MAC length is 20 bytes, then the
 * length before padding is 82 bytes (this does not include the IV. Thus, the
 * padding length modulo 8 must be equal to 6 in order to make the total length
 * an even multiple of 8 bytes (the block length). The padding length can be
 * 6, 14, 22, and so on, through 254. If the padding length were the minimum
 * necessary, 6, the padding would be 6 bytes, each containing the value 6.
 * Thus, the last 8 octets of the GenericBlockCipher before block encryption
 * would be xx 06 06 06 06 06 06 06, where xx is the last octet of the MAC.
 *
 * Note: With block ciphers in CBC mode (Cipher Block Chaining), it is critical
 * that the entire plaintext of the record be known before any ciphertext is
 * transmitted. Otherwise, it is possible for the attacker to mount the attack
 * described in [CBCATT].
 *
 * Implementation note: Canvel et al. [CBCTIME] have demonstrated a timing
 * attack on CBC padding based on the time required to compute the MAC. In
 * order to defend against this attack, implementations MUST ensure that
 * record processing time is essentially the same whether or not the padding
 * is correct. In general, the best way to do this is to compute the MAC even
 * if the padding is incorrect, and only then reject the packet. For instance,
 * if the pad appears to be incorrect, the implementation might assume a
 * zero-length pad and then compute the MAC. This leaves a small timing
 * channel, since MAC performance depends, to some extent, on the size of the
 * data fragment, but it is not believed to be large enough to be exploitable,
 * due to the large block size of existing MACs and the small size of the
 * timing signal.
 */
import { createBuffer, util } from '../utils'
import { create as hmacCreate } from '../utils/hmac'
import { random } from '../utils/random'
import { certificateFromAsn1 } from '../x509'

/**
 * Generates pseudo random bytes by mixing the result of two hash functions,
 * MD5 and SHA-1.
 *
 * prf_TLS1(secret, label, seed) =
 *   P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed);
 *
 * Each P_hash function functions as follows:
 *
 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *                        HMAC_hash(secret, A(2) + seed) +
 *                        HMAC_hash(secret, A(3) + seed) + ...
 * A() is defined as:
 *   A(0) = seed
 *   A(i) = HMAC_hash(secret, A(i-1))
 *
 * The '+' operator denotes concatenation.
 *
 * As many iterations A(N) as are needed are performed to generate enough
 * pseudo random byte output. If an iteration creates more data than is
 * necessary, then it is truncated.
 *
 * Therefore:
 * A(1) = HMAC_hash(secret, A(0))
 *      = HMAC_hash(secret, seed)
 * A(2) = HMAC_hash(secret, A(1))
 *      = HMAC_hash(secret, HMAC_hash(secret, seed))
 *
 * Therefore:
 * P_hash(secret, seed) =
 *   HMAC_hash(secret, HMAC_hash(secret, A(0)) + seed) +
 *   HMAC_hash(secret, HMAC_hash(secret, A(1)) + seed) +
 *   ...
 *
 * Therefore:
 * P_hash(secret, seed) =
 *   HMAC_hash(secret, HMAC_hash(secret, seed) + seed) +
 *   HMAC_hash(secret, HMAC_hash(secret, HMAC_hash(secret, seed)) + seed) +
 *   ...
 *
 * @param secret the secret to use.
 * @param label the label to use.
 * @param seed the seed value to use.
 * @param length the number of bytes to generate.
 *
 * @return the pseudo random bytes in a byte buffer.
 */
function prf_TLS1(secret: string, label: string, seed: string, length: number) {
  const rval = createBuffer()

  /* For TLS 1.0, the secret is split in half, into two secrets of equal
    length. If the secret has an odd length then the last byte of the first
    half will be the same as the first byte of the second. The length of the
    two secrets is half of the secret rounded up. */
  const idx = (secret.length >> 1)
  const slen = idx + (secret.length & 1)
  const s1 = secret.substr(0, slen)
  const s2 = secret.substr(idx, slen)
  const ai = createBuffer()
  const hmac = hmacCreate()
  seed = label + seed

  // determine the number of iterations that must be performed to generate
  // enough output bytes, md5 creates 16 byte hashes, sha1 creates 20
  const md5itr = Math.ceil(length / 16)
  const sha1itr = Math.ceil(length / 20)

  // do md5 iterations
  hmac.start('MD5', s1)
  const md5bytes = createBuffer()
  ai.putBytes(seed)

  for (var i = 0; i < md5itr; ++i) {
    // HMAC_hash(secret, A(i-1))
    hmac.start(null, null)
    hmac.update(ai.getBytes())
    ai.putBuffer(hmac.digest())

    // HMAC_hash(secret, A(i) + seed)
    hmac.start(null, null)
    hmac.update(ai.bytes() + seed)
    md5bytes.putBuffer(hmac.digest())
  }

  // do sha1 iterations
  hmac.start('SHA1', s2)
  const sha1bytes = createBuffer()
  ai.clear()
  ai.putBytes(seed)

  for (var i = 0; i < sha1itr; ++i) {
    // HMAC_hash(secret, A(i-1))
    hmac.start(null, null)
    hmac.update(ai.getBytes())
    ai.putBuffer(hmac.digest())

    // HMAC_hash(secret, A(i) + seed)
    hmac.start(null, null)
    hmac.update(ai.bytes() + seed)
    sha1bytes.putBuffer(hmac.digest())
  }

  // XOR the md5 bytes with the sha1 bytes
  rval.putBytes(util.xorBytes(
    md5bytes.getBytes(),
    sha1bytes.getBytes(),
    length,
  ))

  return rval
}

/**
 * Generates pseudo random bytes using a SHA256 algorithm. For TLS 1.2.
 *
 * @param secret the secret to use.
 * @param label the label to use.
 * @param seed the seed value to use.
 * @param length the number of bytes to generate.
 *
 * @return the pseudo random bytes in a byte buffer.
 */
function prf_sha256(secret: string, label: string, seed: string, length: number) {
  // FIXME: implement me for TLS 1.2
}

interface Record {
  type: number
  version: {
    major: number
    minor: number
  }
  fragment: Buffer
}

/**
 * Gets a MAC for a record using the SHA-1 hash algorithm.
 *
 * @param key the mac key.
 * @param state the sequence number (array of two 32-bit integers).
 * @param record the record.
 *
 * @return the sha-1 hash (20 bytes) for the given record.
 */
function hmac_sha1(key: Buffer, seqNum: number[], record: Record) {
  /* MAC is computed like so:
  HMAC_hash(
    key, seqNum +
      TLSCompressed.type +
      TLSCompressed.version +
      TLSCompressed.length +
      TLSCompressed.fragment)
  */
  const hmac = hmacCreate()
  hmac.start('SHA1', key)
  const b = createBuffer()
  b.putInt32(seqNum[0])
  b.putInt32(seqNum[1])
  b.putByte(record.type)
  b.putByte(record.version.major)
  b.putByte(record.version.minor)
  b.putInt16(record.length)
  b.putBytes(record.fragment.bytes())
  hmac.update(b.getBytes())

  return hmac.digest().getBytes()
}

/**
 * Compresses the TLSPlaintext record into a TLSCompressed record using the
 * deflate algorithm.
 *
 * @param c the TLS connection.
 * @param record the TLSPlaintext record to compress.
 * @param s the ConnectionState to use.
 *
 * @return true on success, false on failure.
 */
function deflate(c: any, record: Record, s: any) {
  let rval = false

  try {
    const bytes = c.deflate(record.fragment.getBytes())
    record.fragment = createBuffer(bytes)
    record.length = bytes.length
    rval = true
  }
  catch (ex) {
    // deflate error, fail out
  }

  return rval
}

/**
 * Decompresses the TLSCompressed record into a TLSPlaintext record using the
 * deflate algorithm.
 *
 * @param c the TLS connection.
 * @param record the TLSCompressed record to decompress.
 * @param s the ConnectionState to use.
 *
 * @return true on success, false on failure.
 */
function inflate(c, record, s) {
  let rval = false

  try {
    const bytes = c.inflate(record.fragment.getBytes())
    record.fragment = createBuffer(bytes)
    record.length = bytes.length
    rval = true
  }
  catch (ex) {
    // inflate error, fail out
  }

  return rval
}

/**
 * Reads a TLS variable-length vector from a byte buffer.
 *
 * Variable-length vectors are defined by specifying a subrange of legal
 * lengths, inclusively, using the notation <floor..ceiling>. When these are
 * encoded, the actual length precedes the vector's contents in the byte
 * stream. The length will be in the form of a number consuming as many bytes
 * as required to hold the vector's specified maximum (ceiling) length. A
 * variable-length vector with an actual length field of zero is referred to
 * as an empty vector.
 *
 * @param b the byte buffer.
 * @param lenBytes the number of bytes required to store the length.
 *
 * @return the resulting byte buffer.
 */
function readVector(b, lenBytes) {
  let len = 0
  switch (lenBytes) {
    case 1:
      len = b.getByte()
      break
    case 2:
      len = b.getInt16()
      break
    case 3:
      len = b.getInt24()
      break
    case 4:
      len = b.getInt32()
      break
  }

  // read vector bytes into a new buffer
  return createBuffer(b.getBytes(len))
}

/**
 * Writes a TLS variable-length vector to a byte buffer.
 *
 * @param b the byte buffer.
 * @param lenBytes the number of bytes required to store the length.
 * @param v the byte buffer vector.
 */
function writeVector(b, lenBytes, v) {
  // encode length at the start of the vector, where the number of bytes for
  // the length is the maximum number of bytes it would take to encode the
  // vector's ceiling
  b.putInt(v.length(), lenBytes << 3)
  b.putBuffer(v)
}

/**
 * The tls implementation.
 */
const tls: any = {}

/**
 * Version: TLS 1.2 = 3.3, TLS 1.1 = 3.2, TLS 1.0 = 3.1. Both TLS 1.1 and
 * TLS 1.2 were still too new (ie: openSSL didn't implement them) at the time
 * of this implementation so TLS 1.0 was implemented instead.
 */
tls.Versions = {
  TLS_1_0: { major: 3, minor: 1 },
  TLS_1_1: { major: 3, minor: 2 },
  TLS_1_2: { major: 3, minor: 3 },
}
tls.SupportedVersions = [
  tls.Versions.TLS_1_1,
  tls.Versions.TLS_1_0,
]
tls.Version = tls.SupportedVersions[0]

/**
 * Maximum fragment size. True maximum is 16384, but we fragment before that
 * to allow for unusual small increases during compression.
 */
tls.MaxFragment = 16384 - 1024

/**
 * Whether this entity is considered the "client" or "server".
 * enum { server, client } ConnectionEnd;
 */
export const ConnectionEnd = {
  server: 0,
  client: 1,
} as const

/**
 * Pseudo-random function algorithm used to generate keys from the master
 * secret.
 * enum { tls_prf_sha256 } PRFAlgorithm;
 */
export const PRFAlgorithm = {
  tls_prf_sha256: 0,
} as const

/**
 * Bulk encryption algorithms.
 * enum { null, rc4, des3, aes } BulkCipherAlgorithm;
 */
export const BulkCipherAlgorithm = {
  none: null,
  rc4: 0,
  des3: 1,
  aes: 2,
} as const

/**
 * Cipher types.
 * enum { stream, block, aead } CipherType;
 */
export const CipherType = {
  stream: 0,
  block: 1,
  aead: 2,
} as const

/**
 * MAC (Message Authentication Code) algorithms.
 * enum { null, hmac_md5, hmac_sha1, hmac_sha256,
 *   hmac_sha384, hmac_sha512} MACAlgorithm;
 */
export const MACAlgorithm = {
  none: null,
  hmac_md5: 0,
  hmac_sha1: 1,
  hmac_sha256: 2,
  hmac_sha384: 3,
  hmac_sha512: 4,
} as const

/**
 * Compression algorithms.
 * enum { null(0), deflate(1), (255) } CompressionMethod;
 */
export const CompressionMethod = {
  none: 0,
  deflate: 1,
} as const

/**
 * TLS record content types.
 * enum {
 *   change_cipher_spec(20), alert(21), handshake(22),
 *   application_data(23), (255)
 * } ContentType;
 */
export const ContentType = {
  change_cipher_spec: 20,
  alert: 21,
  handshake: 22,
  application_data: 23,
  heartbeat: 24,
} as const

/**
 * TLS handshake types.
 * enum {
 *   hello_request(0), client_hello(1), server_hello(2),
 *   certificate(11), server_key_exchange (12),
 *   certificate_request(13), server_hello_done(14),
 *   certificate_verify(15), client_key_exchange(16),
 *   finished(20), (255)
 * } HandshakeType;
 */
export const HandshakeType = {
  hello_request: 0,
  client_hello: 1,
  server_hello: 2,
  certificate: 11,
  server_key_exchange: 12,
  certificate_request: 13,
  server_hello_done: 14,
  certificate_verify: 15,
  client_key_exchange: 16,
  finished: 20,
} as const

/**
 * TLS Alert Protocol.
 *
 * enum { warning(1), fatal(2), (255) } AlertLevel;
 *
 * enum {
 *   close_notify(0),
 *   unexpected_message(10),
 *   bad_record_mac(20),
 *   decryption_failed(21),
 *   record_overflow(22),
 *   decompression_failure(30),
 *   handshake_failure(40),
 *   bad_certificate(42),
 *   unsupported_certificate(43),
 *   certificate_revoked(44),
 *   certificate_expired(45),
 *   certificate_unknown(46),
 *   illegal_parameter(47),
 *   unknown_ca(48),
 *   access_denied(49),
 *   decode_error(50),
 *   decrypt_error(51),
 *   export_restriction(60),
 *   protocol_version(70),
 *   insufficient_security(71),
 *   internal_error(80),
 *   user_canceled(90),
 *   no_renegotiation(100),
 *   (255)
 * } AlertDescription;
 *
 * struct {
 *   AlertLevel level;
 *   AlertDescription description;
 * } Alert;
 */
export const Alert = {
  Level: {
    warning: 1,
    fatal: 2,
  } as const,

  Description: {
    close_notify: 0,
    unexpected_message: 10,
    bad_record_mac: 20,
    decryption_failed: 21,
    record_overflow: 22,
    decompression_failure: 30,
    handshake_failure: 40,
    bad_certificate: 42,
    unsupported_certificate: 43,
    certificate_revoked: 44,
    certificate_expired: 45,
    certificate_unknown: 46,
    illegal_parameter: 47,
    unknown_ca: 48,
    access_denied: 49,
    decode_error: 50,
    decrypt_error: 51,
    export_restriction: 60,
    protocol_version: 70,
    insufficient_security: 71,
    internal_error: 80,
    user_canceled: 90,
    no_renegotiation: 100,
  } as const,
}

/**
 * TLS Heartbeat Message types.
 * enum {
 *   heartbeat_request(1),
 *   heartbeat_response(2),
 *   (255)
 * } HeartbeatMessageType;
 */
export const HeartbeatMessageType = {
  heartbeat_request: 1,
  heartbeat_response: 2,
} as const

/**
 * Supported cipher suites.
 */
export const CipherSuites = {}

/**
 * Gets a supported cipher suite from its 2 byte ID.
 *
 * @param twoBytes two bytes in a string.
 *
 * @return the matching supported cipher suite or null.
 */
export function getCipherSuite(twoBytes: string): CipherSuite | null {
  let rval = null
  for (const key in CipherSuites) {
    const cs = CipherSuites[key]
    if (cs.id[0] === twoBytes.charCodeAt(0)
      && cs.id[1] === twoBytes.charCodeAt(1)) {
      rval = cs
      break
    }
  }
  return rval
}

/**
 * Called when an unexpected record is encountered.
 *
 * @param c the connection.
 * @param record the record.
 */
function handleUnexpected(c: any, record: any) {
  // if connection is client and closed, ignore unexpected messages
  const ignore = (!c.open && c.entity === tls.ConnectionEnd.client)
  if (!ignore) {
    c.error(c, {
      message: 'Unexpected message. Received TLS record out of order.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.unexpected_message,
      },
    })
  }
}

/**
 * Called when a client receives a HelloRequest record.
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleHelloRequest(c: any, record: any, length: number) {
  // ignore renegotiation requests from the server during a handshake, but
  // if handshaking, send a warning alert that renegotation is denied
  if (!c.handshaking && c.handshakes > 0) {
    // send alert warning
    queue(c, tls.createAlert(c, {
      level: Alert.Level.warning,
      description: Alert.Description.no_renegotiation,
    }))
    tls.flush(c)
  }

  // continue
  c.process()
}

/**
 * Parses a hello message from a ClientHello or ServerHello record.
 *
 * @param record the record to parse.
 *
 * @return the parsed message.
 */
function parseHelloMessage(c: any, record: any, length: number) {
  let msg = null

  const client = (c.entity === tls.ConnectionEnd.client)

  // minimum of 38 bytes in message
  if (length < 38) {
    c.error(c, {
      message: client
        ? 'Invalid ServerHello message. Message too short.'
        : 'Invalid ClientHello message. Message too short.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.illegal_parameter,
      },
    })
  }
  else {
    // use 'remaining' to calculate # of remaining bytes in the message
    const b = record.fragment
    let remaining = b.length()
    msg = {
      version: {
        major: b.getByte(),
        minor: b.getByte(),
      },
      random: createBuffer(b.getBytes(32)),
      session_id: readVector(b, 1),
      extensions: [],
    }
    if (client) {
      msg.cipher_suite = b.getBytes(2)
      msg.compression_method = b.getByte()
    }
    else {
      msg.cipher_suites = readVector(b, 2)
      msg.compression_methods = readVector(b, 1)
    }

    // read extensions if there are any bytes left in the message
    remaining = length - (remaining - b.length())
    if (remaining > 0) {
      // parse extensions
      const exts = readVector(b, 2)
      while (exts.length() > 0) {
        msg.extensions.push({
          type: [exts.getByte(), exts.getByte()],
          data: readVector(exts, 2),
        })
      }

      // TODO: make extension support modular
      if (!client) {
        for (let i = 0; i < msg.extensions.length; ++i) {
          const ext = msg.extensions[i]

          // support SNI extension
          if (ext.type[0] === 0x00 && ext.type[1] === 0x00) {
            // get server name list
            const snl = readVector(ext.data, 2)
            while (snl.length() > 0) {
              // read server name type
              const snType = snl.getByte()

              // only HostName type (0x00) is known, break out if
              // another type is detected
              if (snType !== 0x00) {
                break
              }

              // add host name to server name list
              c.session.extensions.server_name.serverNameList.push(
                readVector(snl, 2).getBytes(),
              )
            }
          }
        }
      }
    }

    // version already set, do not allow version change
    if (c.session.version) {
      if (msg.version.major !== c.session.version.major
        || msg.version.minor !== c.session.version.minor) {
        return c.error(c, {
          message: 'TLS version change is disallowed during renegotiation.',
          send: true,
          alert: {
            level: Alert.Level.fatal,
            description: Alert.Description.protocol_version,
          },
        })
      }
    }

    // get the chosen (ServerHello) cipher suite
    if (client) {
      // FIXME: should be checking configured acceptable cipher suites
      c.session.cipherSuite = getCipherSuite(msg.cipher_suite)
    }
    else {
      // get a supported preferred (ClientHello) cipher suite
      // choose the first supported cipher suite
      const tmp = createBuffer(msg.cipher_suites.bytes())
      while (tmp.length() > 0) {
        // FIXME: should be checking configured acceptable suites
        // cipher suites take up 2 bytes
        c.session.cipherSuite = getCipherSuite(tmp.getBytes(2))
        if (c.session.cipherSuite !== null) {
          break
        }
      }
    }

    // cipher suite not supported
    if (c.session.cipherSuite === null) {
      return c.error(c, {
        message: 'No cipher suites in common.',
        send: true,
        alert: {
          level: Alert.Level.fatal,
          description: Alert.Description.handshake_failure,
        },
        cipherSuite: util.bytesToHex(msg.cipher_suite),
      })
    }

    // TODO: handle compression methods
    if (client) {
      c.session.compressionMethod = msg.compression_method
    }
    else {
      // no compression
      c.session.compressionMethod = CompressionMethod.none
    }
  }

  return msg
}

/**
 * Creates security parameters for the given connection based on the given
 * hello message.
 *
 * @param c the TLS connection.
 * @param msg the hello message.
 */
export function createSecurityParameters(c, msg) {
  /* Note: security params are from TLS 1.2, some values like prf_algorithm
  are ignored for TLS 1.0/1.1 and the builtin as specified in the spec is
  used. */

  // TODO: handle other options from server when more supported

  // get client and server randoms
  const client = (c.entity === tls.ConnectionEnd.client)
  const msgRandom = msg.random.bytes()
  const cRandom = client ? c.session.sp.client_random : msgRandom
  const sRandom = client ? msgRandom : tls.createRandom().getBytes()

  // create new security parameters
  c.session.sp = {
    entity: c.entity,
    prf_algorithm: tls.PRFAlgorithm.tls_prf_sha256,
    bulk_cipher_algorithm: null,
    cipher_type: null,
    enc_key_length: null,
    block_length: null,
    fixed_iv_length: null,
    record_iv_length: null,
    mac_algorithm: null,
    mac_length: null,
    mac_key_length: null,
    compression_algorithm: c.session.compressionMethod,
    pre_master_secret: null,
    master_secret: null,
    client_random: cRandom,
    server_random: sRandom,
  }
}

/**
 * Called when a client receives a ServerHello record.
 *
 * When a ServerHello message will be sent:
 *   The server will send this message in response to a client hello message
 *   when it was able to find an acceptable set of algorithms. If it cannot
 *   find such a match, it will respond with a handshake failure alert.
 *
 * uint24 length;
 * struct {
 *   ProtocolVersion server_version;
 *   Random random;
 *   SessionID session_id;
 *   CipherSuite cipher_suite;
 *   CompressionMethod compression_method;
 *   select(extensions_present) {
 *     case false:
 *       struct {};
 *     case true:
 *       Extension extensions<0..2^16-1>;
 *   };
 * } ServerHello;
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleServerHello(c: any, record: any, length: number) {
  const msg = parseHelloMessage(c, record, length)
  if (c.fail) {
    return
  }

  // ensure server version is compatible
  if (msg.version.minor <= c.version.minor) {
    c.version.minor = msg.version.minor
  }
  else {
    return c.error(c, {
      message: 'Incompatible TLS version.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.protocol_version,
      },
    })
  }

  // indicate session version has been set
  c.session.version = c.version

  // get the session ID from the message
  const sessionId = msg.session_id.bytes()

  // if the session ID is not blank and matches the cached one, resume
  // the session
  if (sessionId.length > 0 && sessionId === c.session.id) {
    // resuming session, expect a ChangeCipherSpec next
    c.expect = SCC
    c.session.resuming = true

    // get new server random
    c.session.sp.server_random = msg.random.bytes()
  }
  else {
    // not resuming, expect a server Certificate message next
    c.expect = SCE
    c.session.resuming = false

    // create new security parameters
    createSecurityParameters(c, msg)
  }

  // set new session ID
  c.session.id = sessionId

  // continue
  c.process()
}

/**
 * Called when a server receives a ClientHello record.
 *
 * When a ClientHello message will be sent:
 *   When a client first connects to a server it is required to send the
 *   client hello as its first message. The client can also send a client
 *   hello in response to a hello request or on its own initiative in order
 *   to renegotiate the security parameters in an existing connection.
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleClientHello(c: any, record: any, length: number) {
  const msg = parseHelloMessage(c, record, length)
  if (c.fail) {
    return
  }

  // get the session ID from the message
  let sessionId = msg.session_id.bytes()

  // see if the given session ID is in the cache
  let session = null
  if (c.sessionCache) {
    session = c.sessionCache.getSession(sessionId)
    if (session === null) {
      // session ID not found
      sessionId = ''
    }
    else if (session.version.major !== msg.version.major
      || session.version.minor > msg.version.minor) {
      // if session version is incompatible with client version, do not resume
      session = null
      sessionId = ''
    }
  }

  // no session found to resume, generate a new session ID
  if (sessionId.length === 0) {
    sessionId = random.getBytes(32)
  }

  // update session
  c.session.id = sessionId
  c.session.clientHelloVersion = msg.version
  c.session.sp = {}
  if (session) {
    // use version and security parameters from resumed session
    c.version = c.session.version = session.version
    c.session.sp = session.sp
  }
  else {
    // use highest compatible minor version
    let version
    for (let i = 1; i < tls.SupportedVersions.length; ++i) {
      version = tls.SupportedVersions[i]
      if (version.minor <= msg.version.minor) {
        break
      }
    }
    c.version = { major: version.major, minor: version.minor }
    c.session.version = c.version
  }

  // if a session is set, resume it
  if (session !== null) {
    // resuming session, expect a ChangeCipherSpec next
    c.expect = CCC
    c.session.resuming = true

    // get new client random
    c.session.sp.client_random = msg.random.bytes()
  }
  else {
    // not resuming, expect a Certificate or ClientKeyExchange
    c.expect = (c.verifyClient !== false) ? CCE : CKE
    c.session.resuming = false

    // create new security parameters
    createSecurityParameters(c, msg)
  }

  // connection now open
  c.open = true

  // queue server hello
  queue(c, createRecord(c, {
    type: ContentType.handshake,
    data: createServerHello(c),
  }))

  if (c.session.resuming) {
    // queue change cipher spec message
    queue(c, createRecord(c, {
      type: ContentType.change_cipher_spec,
      data: tls.createChangeCipherSpec(),
    }))

    // create pending state
    c.state.pending = createConnectionState(c)

    // change current write state to pending write state
    c.state.current.write = c.state.pending.write

    // queue finished
    queue(c, createRecord(c, {
      type: ContentType.handshake,
      data: tls.createFinished(c),
    }))
  }
  else {
    // queue server certificate
    queue(c, createRecord(c, {
      type: ContentType.handshake,
      data: tls.createCertificate(c),
    }))

    if (!c.fail) {
      // queue server key exchange
      queue(c, createRecord(c, {
        type: ContentType.handshake,
        data: tls.createServerKeyExchange(c),
      }))

      // request client certificate if set
      if (c.verifyClient !== false) {
        // queue certificate request
        queue(c, createRecord(c, {
          type: ContentType.handshake,
          data: tls.createCertificateRequest(c),
        }))
      }

      // queue server hello done
      queue(c, createRecord(c, {
        type: ContentType.handshake,
        data: createServerHelloDone(c),
      }))
    }
  }

  // send records
  tls.flush(c)

  // continue
  c.process()
}

/**
 * Called when a client receives a Certificate record.
 *
 * When this message will be sent:
 *   The server must send a certificate whenever the agreed-upon key exchange
 *   method is not an anonymous one. This message will always immediately
 *   follow the server hello message.
 *
 * Meaning of this message:
 *   The certificate type must be appropriate for the selected cipher suite's
 *   key exchange algorithm, and is generally an X.509v3 certificate. It must
 *   contain a key which matches the key exchange method, as follows. Unless
 *   otherwise specified, the signing algorithm for the certificate must be
 *   the same as the algorithm for the certificate key. Unless otherwise
 *   specified, the public key may be of any length.
 *
 * opaque ASN.1Cert<1..2^24-1>;
 * struct {
 *   ASN.1Cert certificate_list<1..2^24-1>;
 * } Certificate;
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleCertificate(c: any, record: any, length: number) {
  // minimum of 3 bytes in message
  if (length < 3) {
    return c.error(c, {
      message: 'Invalid Certificate message. Message too short.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.illegal_parameter,
      },
    })
  }

  const b = record.fragment
  const msg = {
    certificate_list: readVector(b, 3),
  }

  /* The sender's certificate will be first in the list (chain), each
    subsequent one that follows will certify the previous one, but root
    certificates (self-signed) that specify the certificate authority may
    be omitted under the assumption that clients must already possess it. */
  let cert
  const certs = []
  try {
    while (msg.certificate_list.length() > 0) {
      // each entry in msg.certificate_list is a vector with 3 len bytes
      cert = readVector(msg.certificate_list, 3)
      cert = certificateFromAsn1(asn1.fromDer(cert), true)
      certs.push(cert)
    }
  }
  catch (ex) {
    return c.error(c, {
      message: 'Could not parse certificate list.',
      cause: ex,
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.bad_certificate,
      },
    })
  }

  // ensure at least 1 certificate was provided if in client-mode
  // or if verifyClient was set to true to require a certificate
  // (as opposed to 'optional')
  const client = (c.entity === tls.ConnectionEnd.client)
  if ((client || c.verifyClient === true) && certs.length === 0) {
    // error, no certificate
    c.error(c, {
      message: client
        ? 'No server certificate provided.'
        : 'No client certificate provided.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.illegal_parameter,
      },
    })
  }
  else if (certs.length === 0) {
    // no certs to verify
    // expect a ServerKeyExchange or ClientKeyExchange message next
    c.expect = client ? SKE : CKE
  }
  else {
    // save certificate in session
    if (client)
      c.session.serverCertificate = certs[0]
    else
      c.session.clientCertificate = certs[0]

    if (verifyCertificateChain(c, certs))
      // expect a ServerKeyExchange or ClientKeyExchange message next
      c.expect = client ? SKE : CKE
  }

  // continue
  c.process()
}

/**
 * Called when a client receives a ServerKeyExchange record.
 *
 * When this message will be sent:
 *   This message will be sent immediately after the server certificate
 *   message (or the server hello message, if this is an anonymous
 *   negotiation).
 *
 *   The server key exchange message is sent by the server only when the
 *   server certificate message (if sent) does not contain enough data to
 *   allow the client to exchange a premaster secret.
 *
 * Meaning of this message:
 *   This message conveys cryptographic information to allow the client to
 *   communicate the premaster secret: either an RSA public key to encrypt
 *   the premaster secret with, or a Diffie-Hellman public key with which the
 *   client can complete a key exchange (with the result being the premaster
 *   secret.)
 *
 * enum {
 *   dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
 * } KeyExchangeAlgorithm;
 *
 * struct {
 *   opaque dh_p<1..2^16-1>;
 *   opaque dh_g<1..2^16-1>;
 *   opaque dh_Ys<1..2^16-1>;
 * } ServerDHParams;
 *
 * struct {
 *   select(KeyExchangeAlgorithm) {
 *     case dh_anon:
 *       ServerDHParams params;
 *     case dhe_dss:
 *     case dhe_rsa:
 *       ServerDHParams params;
 *       digitally-signed struct {
 *         opaque client_random[32];
 *         opaque server_random[32];
 *         ServerDHParams params;
 *       } signed_params;
 *     case rsa:
 *     case dh_dss:
 *     case dh_rsa:
 *       struct {};
 *   };
 * } ServerKeyExchange;
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleServerKeyExchange(c: any, record: any, length: number) {
  // this implementation only supports RSA, no Diffie-Hellman support
  // so any length > 0 is invalid
  if (length > 0) {
    return c.error(c, {
      message: 'Invalid key parameters. Only RSA is supported.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.unsupported_certificate,
      },
    })
  }

  // expect an optional CertificateRequest message next
  c.expect = SCR

  // continue
  c.process()
}

/**
 * Called when a client receives a ClientKeyExchange record.
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleClientKeyExchange(c: any, record: any, length: number) {
  // this implementation only supports RSA, no Diffie-Hellman support
  // so any length < 48 is invalid
  if (length < 48) {
    return c.error(c, {
      message: 'Invalid key parameters. Only RSA is supported.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.unsupported_certificate,
      },
    })
  }

  const b = record.fragment
  const msg = {
    enc_pre_master_secret: readVector(b, 2).getBytes(),
  }

  // do rsa decryption
  let privateKey = null
  if (c.getPrivateKey) {
    try {
      privateKey = c.getPrivateKey(c, c.session.serverCertificate)
      privateKey = pki.privateKeyFromPem(privateKey)
    }
    catch (ex) {
      c.error(c, {
        message: 'Could not get private key.',
        cause: ex,
        send: true,
        alert: {
          level: Alert.Level.fatal,
          description: Alert.Description.internal_error,
        },
      })
    }
  }

  if (privateKey === null) {
    return c.error(c, {
      message: 'No private key set.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.internal_error,
      },
    })
  }

  try {
    // decrypt 48-byte pre-master secret
    var sp = c.session.sp
    sp.pre_master_secret = privateKey.decrypt(msg.enc_pre_master_secret)

    // ensure client hello version matches first 2 bytes
    const version = c.session.clientHelloVersion
    if (version.major !== sp.pre_master_secret.charCodeAt(0)
      || version.minor !== sp.pre_master_secret.charCodeAt(1)) {
      // error, do not send alert (see BLEI attack below)
      throw new Error('TLS version rollback attack detected.')
    }
  }
  catch (ex) {
    /* Note: Daniel Bleichenbacher [BLEI] can be used to attack a
      TLS server which is using PKCS#1 encoded RSA, so instead of
      failing here, we generate 48 random bytes and use that as
      the pre-master secret. */
    sp.pre_master_secret = random.getBytes(48)
  }

  // expect a CertificateVerify message if a Certificate was received that
  // does not have fixed Diffie-Hellman params, otherwise expect
  // ChangeCipherSpec
  c.expect = CCC
  if (c.session.clientCertificate !== null) {
    // only RSA support, so expect CertificateVerify
    // TODO: support Diffie-Hellman
    c.expect = CCV
  }

  // continue
  c.process()
}

/**
 * Called when a client receives a CertificateRequest record.
 *
 * When this message will be sent:
 *   A non-anonymous server can optionally request a certificate from the
 *   client, if appropriate for the selected cipher suite. This message, if
 *   sent, will immediately follow the Server Key Exchange message (if it is
 *   sent; otherwise, the Server Certificate message).
 *
 * enum {
 *   rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
 *   rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
 *   fortezza_dms_RESERVED(20), (255)
 * } ClientCertificateType;
 *
 * opaque DistinguishedName<1..2^16-1>;
 *
 * struct {
 *   ClientCertificateType certificate_types<1..2^8-1>;
 *   SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
 *   DistinguishedName certificate_authorities<0..2^16-1>;
 * } CertificateRequest;
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleCertificateRequest(c: any, record: any, length: number) {
  // minimum of 3 bytes in message
  if (length < 3) {
    return c.error(c, {
      message: 'Invalid CertificateRequest. Message too short.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.illegal_parameter,
      },
    })
  }

  // TODO: TLS 1.2+ has different format including
  // SignatureAndHashAlgorithm after cert types
  const b = record.fragment
  const msg = {
    certificate_types: readVector(b, 1),
    certificate_authorities: readVector(b, 2),
  }

  // save certificate request in session
  c.session.certificateRequest = msg

  // expect a ServerHelloDone message next
  c.expect = SHD

  // continue
  c.process()
}

/**
 * Called when a server receives a CertificateVerify record.
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleCertificateVerify(c: any, record: any, length: number) {
  if (length < 2) {
    return c.error(c, {
      message: 'Invalid CertificateVerify. Message too short.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.illegal_parameter,
      },
    })
  }

  // rewind to get full bytes for message so it can be manually
  // digested below (special case for CertificateVerify messages because
  // they must be digested *after* handling as opposed to all others)
  const b = record.fragment
  b.read -= 4
  const msgBytes = b.bytes()
  b.read += 4

  const msg = {
    signature: readVector(b, 2).getBytes(),
  }

  // TODO: add support for DSA

  // generate data to verify
  let verify = createBuffer()
  verify.putBuffer(c.session.md5.digest())
  verify.putBuffer(c.session.sha1.digest())
  verify = verify.getBytes()

  try {
    const cert = c.session.clientCertificate
    /* b = pki.rsa.decrypt(
      msg.signature, cert.publicKey, true, verify.length);
    if(b !== verify) { */
    if (!cert.publicKey.verify(verify, msg.signature, 'NONE')) {
      throw new Error('CertificateVerify signature does not match.')
    }

    // digest message now that it has been handled
    c.session.md5.update(msgBytes)
    c.session.sha1.update(msgBytes)
  }
  catch (ex) {
    return c.error(c, {
      message: 'Bad signature in CertificateVerify.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.handshake_failure,
      },
    })
  }

  // expect ChangeCipherSpec
  c.expect = CCC

  // continue
  c.process()
}

/**
 * Called when a client receives a ServerHelloDone record.
 *
 * When this message will be sent:
 *   The server hello done message is sent by the server to indicate the end
 *   of the server hello and associated messages. After sending this message
 *   the server will wait for a client response.
 *
 * Meaning of this message:
 *   This message means that the server is done sending messages to support
 *   the key exchange, and the client can proceed with its phase of the key
 *   exchange.
 *
 *   Upon receipt of the server hello done message the client should verify
 *   that the server provided a valid certificate if required and check that
 *   the server hello parameters are acceptable.
 *
 * struct {} ServerHelloDone;
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleServerHelloDone(c: any, record: any, length: number) {
  // len must be 0 bytes
  if (length > 0) {
    return c.error(c, {
      message: 'Invalid ServerHelloDone message. Invalid length.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.record_overflow,
      },
    })
  }

  if (c.serverCertificate === null) {
    // no server certificate was provided
    const error = {
      message: 'No server certificate provided. Not enough security.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.insufficient_security,
      },
    }

    // call application callback
    const depth = 0
    const ret = c.verify(c, error.alert.description, depth, [])
    if (ret !== true) {
      // check for custom alert info
      if (ret || ret === 0) {
        // set custom message and alert description
        if (typeof ret === 'object' && !Array.isArray(ret)) {
          if (ret.message) {
            error.message = ret.message
          }
          if (ret.alert) {
            error.alert.description = ret.alert
          }
        }
        else if (typeof ret === 'number') {
          // set custom alert description
          error.alert.description = ret
        }
      }

      // send error
      return c.error(c, error)
    }
  }

  // create client certificate message if requested
  if (c.session.certificateRequest !== null) {
    record = createRecord(c, {
      type: ContentType.handshake,
      data: tls.createCertificate(c),
    })
    queue(c, record)
  }

  // create client key exchange message
  record = createRecord(c, {
    type: ContentType.handshake,
    data: tls.createClientKeyExchange(c),
  })
  queue(c, record)

  // expect no messages until the following callback has been called
  c.expect = SER

  // create callback to handle client signature (for client-certs)
  const callback = function (c, signature) {
    if (c.session.certificateRequest !== null
      && c.session.clientCertificate !== null) {
      // create certificate verify message
      queue(c, createRecord(c, {
        type: ContentType.handshake,
        data: tls.createCertificateVerify(c, signature),
      }))
    }

    // create change cipher spec message
    queue(c, createRecord(c, {
      type: ContentType.change_cipher_spec,
      data: tls.createChangeCipherSpec(),
    }))

    // create pending state
    c.state.pending = createConnectionState(c)

    // change current write state to pending write state
    c.state.current.write = c.state.pending.write

    // create finished message
    queue(c, createRecord(c, {
      type: ContentType.handshake,
      data: createFinished(c),
    }))

    // expect a server ChangeCipherSpec message next
    c.expect = SCC

    // send records
    tls.flush(c)

    // continue
    c.process()
  }

  // if there is no certificate request or no client certificate, do
  // callback immediately
  if (c.session.certificateRequest === null
    || c.session.clientCertificate === null) {
    return callback(c, null)
  }

  // otherwise get the client signature
  tls.getClientSignature(c, callback)
}

/**
 * Called when a ChangeCipherSpec record is received.
 *
 * @param c the connection.
 * @param record the record.
 */
function handleChangeCipherSpec(c: any, record: any) {
  if (record.fragment.getByte() !== 0x01) {
    return c.error(c, {
      message: 'Invalid ChangeCipherSpec message received.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.illegal_parameter,
      },
    })
  }

  // create pending state if:
  // 1. Resuming session in client mode OR
  // 2. NOT resuming session in server mode
  const client = (c.entity === tls.ConnectionEnd.client)
  if ((c.session.resuming && client) || (!c.session.resuming && !client)) {
    c.state.pending = tls.createConnectionState(c)
  }

  // change current read state to pending read state
  c.state.current.read = c.state.pending.read

  // clear pending state if:
  // 1. NOT resuming session in client mode OR
  // 2. resuming a session in server mode
  if ((!c.session.resuming && client) || (c.session.resuming && !client)) {
    c.state.pending = null
  }

  // expect a Finished record next
  c.expect = client ? SFI : CFI

  // continue
  c.process()
}

/**
 * Called when a Finished record is received.
 *
 * When this message will be sent:
 *   A finished message is always sent immediately after a change
 *   cipher spec message to verify that the key exchange and
 *   authentication processes were successful. It is essential that a
 *   change cipher spec message be received between the other
 *   handshake messages and the Finished message.
 *
 * Meaning of this message:
 *   The finished message is the first protected with the just-
 *   negotiated algorithms, keys, and secrets. Recipients of finished
 *   messages must verify that the contents are correct.  Once a side
 *   has sent its Finished message and received and validated the
 *   Finished message from its peer, it may begin to send and receive
 *   application data over the connection.
 *
 * struct {
 *   opaque verify_data[verify_data_length];
 * } Finished;
 *
 * verify_data
 *   PRF(master_secret, finished_label, Hash(handshake_messages))
 *     [0..verify_data_length-1];
 *
 * finished_label
 *   For Finished messages sent by the client, the string
 *   "client finished". For Finished messages sent by the server, the
 *   string "server finished".
 *
 * verify_data_length depends on the cipher suite. If it is not specified
 * by the cipher suite, then it is 12. Versions of TLS < 1.2 always used
 * 12 bytes.
 *
 * @param c the connection.
 * @param record the record.
 * @param length the length of the handshake message.
 */
function handleFinished(c: any, record: any, length: number) {
  // rewind to get full bytes for message so it can be manually
  // digested below (special case for Finished messages because they
  // must be digested *after* handling as opposed to all others)
  let b = record.fragment
  b.read -= 4
  const msgBytes = b.bytes()
  b.read += 4

  // message contains only verify_data
  const vd = record.fragment.getBytes()

  // ensure verify data is correct
  b = createBuffer()
  b.putBuffer(c.session.md5.digest())
  b.putBuffer(c.session.sha1.digest())

  // set label based on entity type
  const client = (c.entity === tls.ConnectionEnd.client)
  const label = client ? 'server finished' : 'client finished'

  // TODO: determine prf function and verify length for TLS 1.2
  const sp = c.session.sp
  const vdl = 12
  const prf = prf_TLS1
  b = prf(sp.master_secret, label, b.getBytes(), vdl)
  if (b.getBytes() !== vd) {
    return c.error(c, {
      message: 'Invalid verify_data in Finished message.',
      send: true,
      alert: {
        level: Alert.Level.fatal,
        description: Alert.Description.decrypt_error,
      },
    })
  }

  // digest finished message now that it has been handled
  c.session.md5.update(msgBytes)
  c.session.sha1.update(msgBytes)

  // resuming session as client or NOT resuming session as server
  if ((c.session.resuming && client) || (!c.session.resuming && !client)) {
    // create change cipher spec message
    queue(c, createRecord(c, {
      type: ContentType.change_cipher_spec,
      data: tls.createChangeCipherSpec(),
    }))

    // change current write state to pending write state, clear pending
    c.state.current.write = c.state.pending.write
    c.state.pending = null

    // create finished message
    queue(c, createRecord(c, {
      type: ContentType.handshake,
      data: tls.createFinished(c),
    }))
  }

  // expect application data next
  c.expect = client ? SAD : CAD

  // handshake complete
  c.handshaking = false
  ++c.handshakes

  // save access to peer certificate
  c.peerCertificate = client
    ? c.session.serverCertificate
    : c.session.clientCertificate

  // send records
  tls.flush(c)

  // now connected
  c.isConnected = true
  c.connected(c)

  // continue
  c.process()
}

/**
 * Called when an Alert record is received.
 *
 * @param c the connection.
 * @param record the record.
 */
function handleAlert(c: any, record: any) {
  // read alert
  const b = record.fragment
  const alert = {
    level: b.getByte(),
    description: b.getByte(),
  }

  // TODO: consider using a table?
  // get appropriate message
  let msg
  switch (alert.description) {
    case Alert.Description.close_notify:
      msg = 'Connection closed.'
      break
    case Alert.Description.unexpected_message:
      msg = 'Unexpected message.'
      break
    case Alert.Description.bad_record_mac:
      msg = 'Bad record MAC.'
      break
    case Alert.Description.decryption_failed:
      msg = 'Decryption failed.'
      break
    case Alert.Description.record_overflow:
      msg = 'Record overflow.'
      break
    case Alert.Description.decompression_failure:
      msg = 'Decompression failed.'
      break
    case Alert.Description.handshake_failure:
      msg = 'Handshake failure.'
      break
    case Alert.Description.bad_certificate:
      msg = 'Bad certificate.'
      break
    case Alert.Description.unsupported_certificate:
      msg = 'Unsupported certificate.'
      break
    case Alert.Description.certificate_revoked:
      msg = 'Certificate revoked.'
      break
    case Alert.Description.certificate_expired:
      msg = 'Certificate expired.'
      break
    case Alert.Description.certificate_unknown:
      msg = 'Certificate unknown.'
      break
    case Alert.Description.illegal_parameter:
      msg = 'Illegal parameter.'
      break
    case Alert.Description.unknown_ca:
      msg = 'Unknown certificate authority.'
      break
    case Alert.Description.access_denied:
      msg = 'Access denied.'
      break
    case Alert.Description.decode_error:
      msg = 'Decode error.'
      break
    case Alert.Description.decrypt_error:
      msg = 'Decrypt error.'
      break
    case Alert.Description.export_restriction:
      msg = 'Export restriction.'
      break
    case Alert.Description.protocol_version:
      msg = 'Unsupported protocol version.'
      break
    case Alert.Description.insufficient_security:
      msg = 'Insufficient security.'
      break
    case Alert.Description.internal_error:
      msg = 'Internal error.'
      break
    case Alert.Description.user_canceled:
      msg = 'User canceled.'
      break
    case Alert.Description.no_renegotiation:
      msg = 'Renegotiation not supported.'
      break
    default:
      msg = 'Unknown error.'
      break
  }

  // close connection on close_notify, not an error
  if (alert.description === Alert.Description.close_notify) {
    return c.close()
  }

  // call error handler
  c.error(c, {
    message: msg,
    send: false,
    // origin is the opposite end
    origin: (c.entity === tls.ConnectionEnd.client) ? 'server' : 'client',
    alert,
  })

  // continue
  c.process()
}

/**
 * Called when a Handshake record is received.
 *
 * @param c the connection.
 * @param record the record.
 */
function handleHandshake(c: any, record: any) {
  // get the handshake type and message length
  const b = record.fragment
  const type = b.getByte()
  const length = b.getInt24()

  // see if the record fragment doesn't yet contain the full message
  if (length > b.length()) {
    // cache the record, clear its fragment, and reset the buffer read
    // pointer before the type and length were read
    c.fragmented = record
    record.fragment = createBuffer()
    b.read -= 4

    // continue
    return c.process()
  }

  // full message now available, clear cache, reset read pointer to
  // before type and length
  c.fragmented = null
  b.read -= 4

  // save the handshake bytes for digestion after handler is found
  // (include type and length of handshake msg)
  const bytes = b.bytes(length + 4)

  // restore read pointer
  b.read += 4

  // handle expected message
  if (type in hsTable[c.entity][c.expect]) {
    // initialize server session
    if (c.entity === tls.ConnectionEnd.server && !c.open && !c.fail) {
      c.handshaking = true
      c.session = {
        version: null,
        extensions: {
          server_name: {
            serverNameList: [],
          },
        },
        cipherSuite: null,
        compressionMethod: null,
        serverCertificate: null,
        clientCertificate: null,
        md5: forge.md.md5.create(),
        sha1: forge.md.sha1.create(),
      }
    }

    /* Update handshake messages digest. Finished and CertificateVerify
      messages are not digested here. They can't be digested as part of
      the verify_data that they contain. These messages are manually
      digested in their handlers. HelloRequest messages are simply never
      included in the handshake message digest according to spec. */
    if (type !== tls.HandshakeType.hello_request
      && type !== tls.HandshakeType.certificate_verify
      && type !== tls.HandshakeType.finished) {
      c.session.md5.update(bytes)
      c.session.sha1.update(bytes)
    }

    // handle specific handshake type record
    hsTable[c.entity][c.expect][type](c, record, length)
  }
  else {
    // unexpected record
    handleUnexpected(c, record)
  }
}

/**
 * Called when an ApplicationData record is received.
 *
 * @param c the connection.
 * @param record the record.
 */
function handleApplicationData(c: any, record: any) {
  // buffer data, notify that its ready
  c.data.putBuffer(record.fragment)
  c.dataReady(c)

  // continue
  c.process()
}

/**
 * Called when a Heartbeat record is received.
 *
 * @param c the connection.
 * @param record the record.
 */
function handleHeartbeat(c: any, record: any) {
  // get the heartbeat type and payload
  const b = record.fragment
  const type = b.getByte()
  const length = b.getInt16()
  const payload = b.getBytes(length)

  if (type === tls.HeartbeatMessageType.heartbeat_request) {
    // discard request during handshake or if length is too large
    if (c.handshaking || length > payload.length) {
      // continue
      return c.process()
    }
    // retransmit payload
    queue(c, createRecord(c, {
      type: ContentType.heartbeat,
      data: tls.createHeartbeat(
        tls.HeartbeatMessageType.heartbeat_response,
        payload,
      ),
    }))
    tls.flush(c)
  }
  else if (type === tls.HeartbeatMessageType.heartbeat_response) {
    // check payload against expected payload, discard heartbeat if no match
    if (payload !== c.expectedHeartbeatPayload) {
      // continue
      return c.process()
    }

    // notify that a valid heartbeat was received
    if (c.heartbeatReceived) {
      c.heartbeatReceived(c, createBuffer(payload))
    }
  }

  // continue
  c.process()
}

/**
 * The transistional state tables for receiving TLS records. It maps the
 * current TLS engine state and a received record to a function to handle the
 * record and update the state.
 *
 * For instance, if the current state is SHE, then the TLS engine is expecting
 * a ServerHello record. Once a record is received, the handler function is
 * looked up using the state SHE and the record's content type.
 *
 * The resulting function will either be an error handler or a record handler.
 * The function will take whatever action is appropriate and update the state
 * for the next record.
 *
 * The states are all based on possible server record types. Note that the
 * client will never specifically expect to receive a HelloRequest or an alert
 * from the server so there is no state that reflects this. These messages may
 * occur at any time.
 *
 * There are two tables for mapping states because there is a second tier of
 * types for handshake messages. Once a record with a content type of handshake
 * is received, the handshake record handler will look up the handshake type in
 * the secondary map to get its appropriate handler.
 *
 * Valid message orders are as follows:
 *
 * =======================FULL HANDSHAKE======================
 * Client                                               Server
 *
 * ClientHello                  -------->
 *                                                 ServerHello
 *                                                Certificate*
 *                                          ServerKeyExchange*
 *                                         CertificateRequest*
 *                              <--------      ServerHelloDone
 * Certificate*
 * ClientKeyExchange
 * CertificateVerify*
 * [ChangeCipherSpec]
 * Finished                     -------->
 *                                          [ChangeCipherSpec]
 *                              <--------             Finished
 * Application Data             <------->     Application Data
 *
 * =====================SESSION RESUMPTION=====================
 * Client                                                Server
 *
 * ClientHello                   -------->
 *                                                  ServerHello
 *                                           [ChangeCipherSpec]
 *                               <--------             Finished
 * [ChangeCipherSpec]
 * Finished                      -------->
 * Application Data              <------->     Application Data
 */
// client expect states (indicate which records are expected to be received)
const SHE = 0 // rcv server hello
var SCE = 1 // rcv server certificate
var SKE = 2 // rcv server key exchange
var SCR = 3 // rcv certificate request
var SHD = 4 // rcv server hello done
var SCC = 5 // rcv change cipher spec
var SFI = 6 // rcv finished
var SAD = 7 // rcv application data
var SER = 8 // not expecting any messages at this point

// server expect states
const CHE = 0 // rcv client hello
var CCE = 1 // rcv client certificate
var CKE = 2 // rcv client key exchange
var CCV = 3 // rcv certificate verify
var CCC = 4 // rcv change cipher spec
var CFI = 5 // rcv finished
var CAD = 6 // rcv application data
const CER = 7 // not expecting any messages at this point

// map client current expect state and content type to function
const __ = handleUnexpected
const R0 = handleChangeCipherSpec
const R1 = handleAlert
const R2 = handleHandshake
const R3 = handleApplicationData
const R4 = handleHeartbeat
const ctTable = []
ctTable[tls.ConnectionEnd.client] = [
//      CC,AL,HS,AD,HB
/* SHE */[__, R1, R2, __, R4],
  /* SCE */[__, R1, R2, __, R4],
  /* SKE */[__, R1, R2, __, R4],
  /* SCR */[__, R1, R2, __, R4],
  /* SHD */[__, R1, R2, __, R4],
  /* SCC */[R0, R1, __, __, R4],
  /* SFI */[__, R1, R2, __, R4],
  /* SAD */[__, R1, R2, R3, R4],
  /* SER */[__, R1, R2, __, R4],
]

// map server current expect state and content type to function
ctTable[tls.ConnectionEnd.server] = [
//      CC,AL,HS,AD
/* CHE */[__, R1, R2, __, R4],
  /* CCE */[__, R1, R2, __, R4],
  /* CKE */[__, R1, R2, __, R4],
  /* CCV */[__, R1, R2, __, R4],
  /* CCC */[R0, R1, __, __, R4],
  /* CFI */[__, R1, R2, __, R4],
  /* CAD */[__, R1, R2, R3, R4],
  /* CER */[__, R1, R2, __, R4],
]

// map client current expect state and handshake type to function
const H0 = handleHelloRequest
const H1 = handleServerHello
const H2 = handleCertificate
const H3 = handleServerKeyExchange
const H4 = handleCertificateRequest
const H5 = handleServerHelloDone
const H6 = handleFinished
let hsTable: any = []
hsTable[tls.ConnectionEnd.client] = [
//      HR,01,SH,03,04,05,06,07,08,09,10,SC,SK,CR,HD,15,CK,17,18,19,FI
/* SHE */[__, __, H1, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
  /* SCE */[H0, __, __, __, __, __, __, __, __, __, __, H2, H3, H4, H5, __, __, __, __, __, __],
  /* SKE */[H0, __, __, __, __, __, __, __, __, __, __, __, H3, H4, H5, __, __, __, __, __, __],
  /* SCR */[H0, __, __, __, __, __, __, __, __, __, __, __, __, H4, H5, __, __, __, __, __, __],
  /* SHD */[H0, __, __, __, __, __, __, __, __, __, __, __, __, __, H5, __, __, __, __, __, __],
  /* SCC */[H0, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
  /* SFI */[H0, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, H6],
  /* SAD */[H0, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
  /* SER */[H0, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
]

// map server current expect state and handshake type to function
// Note: CAD[CH] does not map to FB because renegotation is prohibited
const H7 = handleClientHello
const H8 = handleClientKeyExchange
const H9 = handleCertificateVerify
hsTable[tls.ConnectionEnd.server] = [
//      01,CH,02,03,04,05,06,07,08,09,10,CC,12,13,14,CV,CK,17,18,19,FI
/* CHE */[__, H7, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
  /* CCE */[__, __, __, __, __, __, __, __, __, __, __, H2, __, __, __, __, __, __, __, __, __],
  /* CKE */[__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, H8, __, __, __, __],
  /* CCV */[__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, H9, __, __, __, __, __],
  /* CCC */[__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
  /* CFI */[__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, H6],
  /* CAD */[__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
  /* CER */[__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __],
]

/**
 * Generates the master_secret and keys using the given security parameters.
 *
 * The security parameters for a TLS connection state are defined as such:
 *
 * struct {
 *   ConnectionEnd          entity;
 *   PRFAlgorithm           prf_algorithm;
 *   BulkCipherAlgorithm    bulk_cipher_algorithm;
 *   CipherType             cipher_type;
 *   uint8                  enc_key_length;
 *   uint8                  block_length;
 *   uint8                  fixed_iv_length;
 *   uint8                  record_iv_length;
 *   MACAlgorithm           mac_algorithm;
 *   uint8                  mac_length;
 *   uint8                  mac_key_length;
 *   CompressionMethod      compression_algorithm;
 *   opaque                 master_secret[48];
 *   opaque                 client_random[32];
 *   opaque                 server_random[32];
 * } SecurityParameters;
 *
 * Note that this definition is from TLS 1.2. In TLS 1.0 some of these
 * parameters are ignored because, for instance, the PRFAlgorithm is a
 * builtin-fixed algorithm combining iterations of MD5 and SHA-1 in TLS 1.0.
 *
 * The Record Protocol requires an algorithm to generate keys required by the
 * current connection state.
 *
 * The master secret is expanded into a sequence of secure bytes, which is then
 * split to a client write MAC key, a server write MAC key, a client write
 * encryption key, and a server write encryption key. In TLS 1.0 a client write
 * IV and server write IV are also generated. Each of these is generated from
 * the byte sequence in that order. Unused values are empty. In TLS 1.2, some
 * AEAD ciphers may additionally require a client write IV and a server write
 * IV (see Section 6.2.3.3).
 *
 * When keys, MAC keys, and IVs are generated, the master secret is used as an
 * entropy source.
 *
 * To generate the key material, compute:
 *
 * master_secret = PRF(pre_master_secret, "master secret",
 *                     ClientHello.random + ServerHello.random)
 *
 * key_block = PRF(SecurityParameters.master_secret,
 *                 "key expansion",
 *                 SecurityParameters.server_random +
 *                 SecurityParameters.client_random);
 *
 * until enough output has been generated. Then, the key_block is
 * partitioned as follows:
 *
 * client_write_MAC_key[SecurityParameters.mac_key_length]
 * server_write_MAC_key[SecurityParameters.mac_key_length]
 * client_write_key[SecurityParameters.enc_key_length]
 * server_write_key[SecurityParameters.enc_key_length]
 * client_write_IV[SecurityParameters.fixed_iv_length]
 * server_write_IV[SecurityParameters.fixed_iv_length]
 *
 * In TLS 1.2, the client_write_IV and server_write_IV are only generated for
 * implicit nonce techniques as described in Section 3.2.1 of [AEAD]. This
 * implementation uses TLS 1.0 so IVs are generated.
 *
 * Implementation note: The currently defined cipher suite which requires the
 * most material is AES_256_CBC_SHA256. It requires 2 x 32 byte keys and 2 x 32
 * byte MAC keys, for a total 128 bytes of key material. In TLS 1.0 it also
 * requires 2 x 16 byte IVs, so it actually takes 160 bytes of key material.
 *
 * @param c the connection.
 * @param sp the security parameters to use.
 *
 * @return the security keys.
 */
function generateKeys(c, sp) {
  // TLS_RSA_WITH_AES_128_CBC_SHA (required to be compliant with TLS 1.2) &
  // TLS_RSA_WITH_AES_256_CBC_SHA are the only cipher suites implemented
  // at present

  // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA is required to be compliant with
  // TLS 1.0 but we don't care right now because AES is better and we have
  // an implementation for it

  // TODO: TLS 1.2 implementation
  /*
  // determine the PRF
  var prf;
  switch(sp.prf_algorithm) {
  case tls.PRFAlgorithm.tls_prf_sha256:
    prf = prf_sha256;
    break;
  default:
    // should never happen
    throw new Error('Invalid PRF');
  }
  */

  // TLS 1.0/1.1 implementation
  const prf = prf_TLS1

  // concatenate server and client random
  let random = sp.client_random + sp.server_random

  // only create master secret if session is new
  if (!c.session.resuming) {
    // create master secret, clean up pre-master secret
    sp.master_secret = prf(
      sp.pre_master_secret,
      'master secret',
      random,
      48,
    ).bytes()
    sp.pre_master_secret = null
  }

  // generate the amount of key material needed
  random = sp.server_random + sp.client_random
  let length = 2 * sp.mac_key_length + 2 * sp.enc_key_length

  // include IV for TLS/1.0
  const tls10 = (c.version.major === tls.Versions.TLS_1_0.major
    && c.version.minor === tls.Versions.TLS_1_0.minor)
  if (tls10) {
    length += 2 * sp.fixed_iv_length
  }
  const km = prf(sp.master_secret, 'key expansion', random, length)

  // split the key material into the MAC and encryption keys
  const rval = {
    client_write_MAC_key: km.getBytes(sp.mac_key_length),
    server_write_MAC_key: km.getBytes(sp.mac_key_length),
    client_write_key: km.getBytes(sp.enc_key_length),
    server_write_key: km.getBytes(sp.enc_key_length),
  }

  // include TLS 1.0 IVs
  if (tls10) {
    rval.client_write_IV = km.getBytes(sp.fixed_iv_length)
    rval.server_write_IV = km.getBytes(sp.fixed_iv_length)
  }

  return rval
}

/**
 * Creates a new initialized TLS connection state. A connection state has
 * a read mode and a write mode.
 *
 * compression state:
 *   The current state of the compression algorithm.
 *
 * cipher state:
 *   The current state of the encryption algorithm. This will consist of the
 *   scheduled key for that connection. For stream ciphers, this will also
 *   contain whatever state information is necessary to allow the stream to
 *   continue to encrypt or decrypt data.
 *
 * MAC key:
 *   The MAC key for the connection.
 *
 * sequence number:
 *   Each connection state contains a sequence number, which is maintained
 *   separately for read and write states. The sequence number MUST be set to
 *   zero whenever a connection state is made the active state. Sequence
 *   numbers are of type uint64 and may not exceed 2^64-1. Sequence numbers do
 *   not wrap. If a TLS implementation would need to wrap a sequence number,
 *   it must renegotiate instead. A sequence number is incremented after each
 *   record: specifically, the first record transmitted under a particular
 *   connection state MUST use sequence number 0.
 *
 * @param c the connection.
 *
 * @return the new initialized TLS connection state.
 */
function createConnectionState(c) {
  const client = (c.entity === tls.ConnectionEnd.client)

  const createMode = function () {
    var mode = {
      // two 32-bit numbers, first is most significant
      sequenceNumber: [0, 0],
      macKey: null,
      macLength: 0,
      macFunction: null,
      cipherState: null,
      cipherFunction(record) { return true },
      compressionState: null,
      compressFunction(record) { return true },
      updateSequenceNumber() {
        if (mode.sequenceNumber[1] === 0xFFFFFFFF) {
          mode.sequenceNumber[1] = 0
          ++mode.sequenceNumber[0]
        }
        else {
          ++mode.sequenceNumber[1]
        }
      },
    }
    return mode
  }
  const state = {
    read: createMode(),
    write: createMode(),
  }

  // update function in read mode will decrypt then decompress a record
  state.read.update = function (c, record) {
    if (!state.read.cipherFunction(record, state.read)) {
      c.error(c, {
        message: 'Could not decrypt record or bad MAC.',
        send: true,
        alert: {
          level: Alert.Level.fatal,
          // doesn't matter if decryption failed or MAC was
          // invalid, return the same error so as not to reveal
          // which one occurred
          description: Alert.Description.bad_record_mac,
        },
      })
    }
    else if (!state.read.compressFunction(c, record, state.read)) {
      c.error(c, {
        message: 'Could not decompress record.',
        send: true,
        alert: {
          level: Alert.Level.fatal,
          description: Alert.Description.decompression_failure,
        },
      })
    }
    return !c.fail
  }

  // update function in write mode will compress then encrypt a record
  state.write.update = function (c, record) {
    if (!state.write.compressFunction(c, record, state.write)) {
      // error, but do not send alert since it would require
      // compression as well
      c.error(c, {
        message: 'Could not compress record.',
        send: false,
        alert: {
          level: Alert.Level.fatal,
          description: Alert.Description.internal_error,
        },
      })
    }
    else if (!state.write.cipherFunction(record, state.write)) {
      // error, but do not send alert since it would require
      // encryption as well
      c.error(c, {
        message: 'Could not encrypt record.',
        send: false,
        alert: {
          level: Alert.Level.fatal,
          description: Alert.Description.internal_error,
        },
      })
    }
    return !c.fail
  }

  // handle security parameters
  if (c.session) {
    const sp = c.session.sp
    c.session.cipherSuite.initSecurityParameters(sp)

    // generate keys
    sp.keys = generateKeys(c, sp)
    state.read.macKey = client
      ? sp.keys.server_write_MAC_key
      : sp.keys.client_write_MAC_key
    state.write.macKey = client
      ? sp.keys.client_write_MAC_key
      : sp.keys.server_write_MAC_key

    // cipher suite setup
    c.session.cipherSuite.initConnectionState(state, c, sp)

    // compression setup
    switch (sp.compression_algorithm) {
      case CompressionMethod.none:
        break
      case CompressionMethod.deflate:
        state.read.compressFunction = inflate
        state.write.compressFunction = deflate
        break
      default:
        throw new Error('Unsupported compression algorithm.')
    }
  }

  return state
}

/**
 * Creates a Random structure.
 *
 * struct {
 *   uint32 gmt_unix_time;
 *   opaque random_bytes[28];
 * } Random;
 *
 * gmt_unix_time:
 *   The current time and date in standard UNIX 32-bit format (seconds since
 *   the midnight starting Jan 1, 1970, UTC, ignoring leap seconds) according
 *   to the sender's internal clock. Clocks are not required to be set
 *   correctly by the basic TLS protocol; higher-level or application
 *   protocols may define additional requirements. Note that, for historical
 *   reasons, the data element is named using GMT, the predecessor of the
 *   current worldwide time base, UTC.
 * random_bytes:
 *   28 bytes generated by a secure random number generator.
 *
 * @return the Random structure as a byte array.
 */
tls.createRandom = function () {
  // get UTC milliseconds
  const d = new Date()
  const utc = +d + d.getTimezoneOffset() * 60000
  const rval = createBuffer()
  rval.putInt32(utc)
  rval.putBytes(random.getBytes(28))
  return rval
}

/**
 * Creates a TLS record with the given type and data.
 *
 * @param c the connection.
 * @param options:
 *   type: the record type.
 *   data: the plain text data in a byte buffer.
 *
 * @return the created record.
 */
function createRecord(c, options) {
  if (!options.data) {
    return null
  }
  const record = {
    type: options.type,
    version: {
      major: c.version.major,
      minor: c.version.minor,
    },
    length: options.data.length(),
    fragment: options.data,
  }
  return record
}

/**
 * Creates a TLS alert record.
 *
 * @param c the connection.
 * @param alert:
 *   level: the TLS alert level.
 *   description: the TLS alert description.
 *
 * @return the created alert record.
 */
tls.createAlert = function (c, alert) {
  const b = createBuffer()
  b.putByte(alert.level)
  b.putByte(alert.description)
  return createRecord(c, {
    type: ContentType.alert,
    data: b,
  })
}

/* The structure of a TLS handshake message.
 *
 * struct {
 *    HandshakeType msg_type;    // handshake type
 *    uint24 length;             // bytes in message
 *    select(HandshakeType) {
 *       case hello_request:       HelloRequest;
 *       case client_hello:        ClientHello;
 *       case server_hello:        ServerHello;
 *       case certificate:         Certificate;
 *       case server_key_exchange: ServerKeyExchange;
 *       case certificate_request: CertificateRequest;
 *       case server_hello_done:   ServerHelloDone;
 *       case certificate_verify:  CertificateVerify;
 *       case client_key_exchange: ClientKeyExchange;
 *       case finished:            Finished;
 *    } body;
 * } Handshake;
 */

/**
 * Creates a ClientHello message.
 *
 * opaque SessionID<0..32>;
 * enum { null(0), deflate(1), (255) } CompressionMethod;
 * uint8 CipherSuite[2];
 *
 * struct {
 *   ProtocolVersion client_version;
 *   Random random;
 *   SessionID session_id;
 *   CipherSuite cipher_suites<2..2^16-2>;
 *   CompressionMethod compression_methods<1..2^8-1>;
 *   select(extensions_present) {
 *     case false:
 *       struct {};
 *     case true:
 *       Extension extensions<0..2^16-1>;
 *   };
 * } ClientHello;
 *
 * The extension format for extended client hellos and server hellos is:
 *
 * struct {
 *   ExtensionType extension_type;
 *   opaque extension_data<0..2^16-1>;
 * } Extension;
 *
 * Here:
 *
 * - "extension_type" identifies the particular extension type.
 * - "extension_data" contains information specific to the particular
 * extension type.
 *
 * The extension types defined in this document are:
 *
 * enum {
 *   server_name(0), max_fragment_length(1),
 *   client_certificate_url(2), trusted_ca_keys(3),
 *   truncated_hmac(4), status_request(5), (65535)
 * } ExtensionType;
 *
 * @param c the connection.
 *
 * @return the ClientHello byte buffer.
 */
tls.createClientHello = function (c) {
  // save hello version
  c.session.clientHelloVersion = {
    major: c.version.major,
    minor: c.version.minor,
  }

  // create supported cipher suites
  const cipherSuites = createBuffer()
  for (let i = 0; i < c.cipherSuites.length; ++i) {
    const cs = c.cipherSuites[i]
    cipherSuites.putByte(cs.id[0])
    cipherSuites.putByte(cs.id[1])
  }
  const cSuites = cipherSuites.length()

  // create supported compression methods, null always supported, but
  // also support deflate if connection has inflate and deflate methods
  const compressionMethods = createBuffer()
  compressionMethods.putByte(CompressionMethod.none)
  // FIXME: deflate support disabled until issues with raw deflate data
  // without zlib headers are resolved
  /*
  if(c.inflate !== null && c.deflate !== null) {
    compressionMethods.putByte(CompressionMethod.deflate);
  }
  */
  const cMethods = compressionMethods.length()

  // create TLS SNI (server name indication) extension if virtual host
  // has been specified, see RFC 3546
  const extensions = createBuffer()
  if (c.virtualHost) {
    // create extension struct
    const ext = createBuffer()
    ext.putByte(0x00) // type server_name (ExtensionType is 2 bytes)
    ext.putByte(0x00)

    /* In order to provide the server name, clients MAY include an
     * extension of type "server_name" in the (extended) client hello.
     * The "extension_data" field of this extension SHALL contain
     * "ServerNameList" where:
     *
     * struct {
     *   NameType name_type;
     *   select(name_type) {
     *     case host_name: HostName;
     *   } name;
     * } ServerName;
     *
     * enum {
     *   host_name(0), (255)
     * } NameType;
     *
     * opaque HostName<1..2^16-1>;
     *
     * struct {
     *   ServerName server_name_list<1..2^16-1>
     * } ServerNameList;
     */
    const serverName = createBuffer()
    serverName.putByte(0x00) // type host_name
    writeVector(serverName, 2, createBuffer(c.virtualHost))

    // ServerNameList is in extension_data
    const snList = createBuffer()
    writeVector(snList, 2, serverName)
    writeVector(ext, 2, snList)
    extensions.putBuffer(ext)
  }
  let extLength = extensions.length()
  if (extLength > 0) {
    // add extension vector length
    extLength += 2
  }

  // determine length of the handshake message
  // cipher suites and compression methods size will need to be
  // updated if more get added to the list
  const sessionId = c.session.id
  const length
    = sessionId.length + 1 // session ID vector
      + 2 // version (major + minor)
      + 4 + 28 // random time and random bytes
      + 2 + cSuites // cipher suites vector
      + 1 + cMethods // compression methods vector
      + extLength // extensions vector

  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.client_hello)
  rval.putInt24(length) // handshake length
  rval.putByte(c.version.major) // major version
  rval.putByte(c.version.minor) // minor version
  rval.putBytes(c.session.sp.client_random) // random time + bytes
  writeVector(rval, 1, createBuffer(sessionId))
  writeVector(rval, 2, cipherSuites)
  writeVector(rval, 1, compressionMethods)
  if (extLength > 0) {
    writeVector(rval, 2, extensions)
  }
  return rval
}

/**
 * Creates a ServerHello message.
 *
 * @param c the connection.
 *
 * @return the ServerHello byte buffer.
 */
function createServerHello(c: any) {
  // determine length of the handshake message
  const sessionId = c.session.id
  const length
    = sessionId.length + 1 // session ID vector
      + 2 // version (major + minor)
      + 4 + 28 // random time and random bytes
      + 2 // chosen cipher suite
      + 1 // chosen compression method

  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.server_hello)
  rval.putInt24(length) // handshake length
  rval.putByte(c.version.major) // major version
  rval.putByte(c.version.minor) // minor version
  rval.putBytes(c.session.sp.server_random) // random time + bytes
  writeVector(rval, 1, createBuffer(sessionId))
  rval.putByte(c.session.cipherSuite.id[0])
  rval.putByte(c.session.cipherSuite.id[1])
  rval.putByte(c.session.compressionMethod)
  return rval
}

/**
 * Creates a Certificate message.
 *
 * When this message will be sent:
 *   This is the first message the client can send after receiving a server
 *   hello done message and the first message the server can send after
 *   sending a ServerHello. This client message is only sent if the server
 *   requests a certificate. If no suitable certificate is available, the
 *   client should send a certificate message containing no certificates. If
 *   client authentication is required by the server for the handshake to
 *   continue, it may respond with a fatal handshake failure alert.
 *
 * opaque ASN.1Cert<1..2^24-1>;
 *
 * struct {
 *   ASN.1Cert certificate_list<0..2^24-1>;
 * } Certificate;
 *
 * @param c the connection.
 *
 * @return the Certificate byte buffer.
 */
tls.createCertificate = function (c) {
  // TODO: check certificate request to ensure types are supported

  // get a certificate (a certificate as a PEM string)
  const client = (c.entity === tls.ConnectionEnd.client)
  let cert = null
  if (c.getCertificate) {
    let hint
    if (client) {
      hint = c.session.certificateRequest
    }
    else {
      hint = c.session.extensions.server_name.serverNameList
    }
    cert = c.getCertificate(c, hint)
  }

  // buffer to hold certificate list
  const certList = createBuffer()
  if (cert !== null) {
    try {
      // normalize cert to a chain of certificates
      if (!Array.isArray(cert)) {
        cert = [cert]
      }
      let asn1 = null
      for (let i = 0; i < cert.length; ++i) {
        const msg = forge.pem.decode(cert[i])[0]
        if (msg.type !== 'CERTIFICATE'
          && msg.type !== 'X509 CERTIFICATE'
          && msg.type !== 'TRUSTED CERTIFICATE') {
          const error = new Error('Could not convert certificate from PEM; PEM '
            + 'header type is not "CERTIFICATE", "X509 CERTIFICATE", or '
            + '"TRUSTED CERTIFICATE".')
          error.headerType = msg.type
          throw error
        }
        if (msg.procType && msg.procType.type === 'ENCRYPTED') {
          throw new Error('Could not convert certificate from PEM; PEM is encrypted.')
        }

        const der = createBuffer(msg.body)
        if (asn1 === null) {
          asn1 = asn1.fromDer(der.bytes(), false)
        }

        // certificate entry is itself a vector with 3 length bytes
        const certBuffer = createBuffer()
        writeVector(certBuffer, 3, der)

        // add cert vector to cert list vector
        certList.putBuffer(certBuffer)
      }

      // save certificate
      cert = certificateFromAsn1(asn1)
      if (client) {
        c.session.clientCertificate = cert
      }
      else {
        c.session.serverCertificate = cert
      }
    }
    catch (ex) {
      return c.error(c, {
        message: 'Could not send certificate list.',
        cause: ex,
        send: true,
        alert: {
          level: Alert.Level.fatal,
          description: Alert.Description.bad_certificate,
        },
      })
    }
  }

  // determine length of the handshake message
  const length = 3 + certList.length() // cert list vector

  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.certificate)
  rval.putInt24(length)
  writeVector(rval, 3, certList)
  return rval
}

/**
 * Creates a ClientKeyExchange message.
 *
 * When this message will be sent:
 *   This message is always sent by the client. It will immediately follow the
 *   client certificate message, if it is sent. Otherwise it will be the first
 *   message sent by the client after it receives the server hello done
 *   message.
 *
 * Meaning of this message:
 *   With this message, the premaster secret is set, either though direct
 *   transmission of the RSA-encrypted secret, or by the transmission of
 *   Diffie-Hellman parameters which will allow each side to agree upon the
 *   same premaster secret. When the key exchange method is DH_RSA or DH_DSS,
 *   client certification has been requested, and the client was able to
 *   respond with a certificate which contained a Diffie-Hellman public key
 *   whose parameters (group and generator) matched those specified by the
 *   server in its certificate, this message will not contain any data.
 *
 * Meaning of this message:
 *   If RSA is being used for key agreement and authentication, the client
 *   generates a 48-byte premaster secret, encrypts it using the public key
 *   from the server's certificate or the temporary RSA key provided in a
 *   server key exchange message, and sends the result in an encrypted
 *   premaster secret message. This structure is a variant of the client
 *   key exchange message, not a message in itself.
 *
 * struct {
 *   select(KeyExchangeAlgorithm) {
 *     case rsa: EncryptedPreMasterSecret;
 *     case diffie_hellman: ClientDiffieHellmanPublic;
 *   } exchange_keys;
 * } ClientKeyExchange;
 *
 * struct {
 *   ProtocolVersion client_version;
 *   opaque random[46];
 * } PreMasterSecret;
 *
 * struct {
 *   public-key-encrypted PreMasterSecret pre_master_secret;
 * } EncryptedPreMasterSecret;
 *
 * A public-key-encrypted element is encoded as a vector <0..2^16-1>.
 *
 * @param c the connection.
 *
 * @return the ClientKeyExchange byte buffer.
 */
tls.createClientKeyExchange = function (c) {
  // create buffer to encrypt
  let b = createBuffer()

  // add highest client-supported protocol to help server avoid version
  // rollback attacks
  b.putByte(c.session.clientHelloVersion.major)
  b.putByte(c.session.clientHelloVersion.minor)

  // generate and add 46 random bytes
  b.putBytes(random.getBytes(46))

  // save pre-master secret
  const sp = c.session.sp
  sp.pre_master_secret = b.getBytes()

  // RSA-encrypt the pre-master secret
  const key = c.session.serverCertificate.publicKey
  b = key.encrypt(sp.pre_master_secret)

  /* Note: The encrypted pre-master secret will be stored in a
    public-key-encrypted opaque vector that has the length prefixed using
    2 bytes, so include those 2 bytes in the handshake message length. This
    is done as a minor optimization instead of calling writeVector(). */

  // determine length of the handshake message
  const length = b.length + 2

  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.client_key_exchange)
  rval.putInt24(length)
  // add vector length bytes
  rval.putInt16(b.length)
  rval.putBytes(b)
  return rval
}

/**
 * Creates a ServerKeyExchange message.
 *
 * @param c the connection.
 *
 * @return the ServerKeyExchange byte buffer.
 */
tls.createServerKeyExchange = function (c) {
  // this implementation only supports RSA, no Diffie-Hellman support,
  // so this record is empty

  // determine length of the handshake message
  const length = 0

  // build record fragment
  const rval = createBuffer()
  if (length > 0) {
    rval.putByte(tls.HandshakeType.server_key_exchange)
    rval.putInt24(length)
  }
  return rval
}

/**
 * Gets the signed data used to verify a client-side certificate. See
 * tls.createCertificateVerify() for details.
 *
 * @param c the connection.
 * @param callback the callback to call once the signed data is ready.
 */
tls.getClientSignature = function (c, callback) {
  // generate data to RSA encrypt
  let b = createBuffer()
  b.putBuffer(c.session.md5.digest())
  b.putBuffer(c.session.sha1.digest())
  b = b.getBytes()

  // create default signing function as necessary
  c.getSignature = c.getSignature || function (c, b, callback) {
    // do rsa encryption, call callback
    let privateKey = null
    if (c.getPrivateKey) {
      try {
        privateKey = c.getPrivateKey(c, c.session.clientCertificate)
        privateKey = pki.privateKeyFromPem(privateKey)
      }
      catch (ex) {
        c.error(c, {
          message: 'Could not get private key.',
          cause: ex,
          send: true,
          alert: {
            level: Alert.Level.fatal,
            description: Alert.Description.internal_error,
          },
        })
      }
    }
    if (privateKey === null) {
      c.error(c, {
        message: 'No private key set.',
        send: true,
        alert: {
          level: Alert.Level.fatal,
          description: Alert.Description.internal_error,
        },
      })
    }
    else {
      b = privateKey.sign(b, null)
    }
    callback(c, b)
  }

  // get client signature
  c.getSignature(c, b, callback)
}

/**
 * Creates a CertificateVerify message.
 *
 * Meaning of this message:
 *   This structure conveys the client's Diffie-Hellman public value
 *   (Yc) if it was not already included in the client's certificate.
 *   The encoding used for Yc is determined by the enumerated
 *   PublicValueEncoding. This structure is a variant of the client
 *   key exchange message, not a message in itself.
 *
 * When this message will be sent:
 *   This message is used to provide explicit verification of a client
 *   certificate. This message is only sent following a client
 *   certificate that has signing capability (i.e. all certificates
 *   except those containing fixed Diffie-Hellman parameters). When
 *   sent, it will immediately follow the client key exchange message.
 *
 * struct {
 *   Signature signature;
 * } CertificateVerify;
 *
 * CertificateVerify.signature.md5_hash
 *   MD5(handshake_messages);
 *
 * Certificate.signature.sha_hash
 *   SHA(handshake_messages);
 *
 * Here handshake_messages refers to all handshake messages sent or
 * received starting at client hello up to but not including this
 * message, including the type and length fields of the handshake
 * messages.
 *
 * select(SignatureAlgorithm) {
 *   case anonymous: struct { };
 *   case rsa:
 *     digitally-signed struct {
 *       opaque md5_hash[16];
 *       opaque sha_hash[20];
 *     };
 *   case dsa:
 *     digitally-signed struct {
 *       opaque sha_hash[20];
 *     };
 * } Signature;
 *
 * In digital signing, one-way hash functions are used as input for a
 * signing algorithm. A digitally-signed element is encoded as an opaque
 * vector <0..2^16-1>, where the length is specified by the signing
 * algorithm and key.
 *
 * In RSA signing, a 36-byte structure of two hashes (one SHA and one
 * MD5) is signed (encrypted with the private key). It is encoded with
 * PKCS #1 block type 0 or type 1 as described in [PKCS1].
 *
 * In DSS, the 20 bytes of the SHA hash are run directly through the
 * Digital Signing Algorithm with no additional hashing.
 *
 * @param c the connection.
 * @param signature the signature to include in the message.
 *
 * @return the CertificateVerify byte buffer.
 */
tls.createCertificateVerify = function (c, signature) {
  /* Note: The signature will be stored in a "digitally-signed" opaque
    vector that has the length prefixed using 2 bytes, so include those
    2 bytes in the handshake message length. This is done as a minor
    optimization instead of calling writeVector(). */

  // determine length of the handshake message
  const length = signature.length + 2

  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.certificate_verify)
  rval.putInt24(length)
  // add vector length bytes
  rval.putInt16(signature.length)
  rval.putBytes(signature)
  return rval
}

/**
 * Creates a CertificateRequest message.
 *
 * @param c the connection.
 *
 * @return the CertificateRequest byte buffer.
 */
tls.createCertificateRequest = function (c) {
  // TODO: support other certificate types
  const certTypes = createBuffer()

  // common RSA certificate type
  certTypes.putByte(0x01)

  // add distinguished names from CA store
  const cAs = createBuffer()
  for (const key in c.caStore.certs) {
    const cert = c.caStore.certs[key]
    const dn = pki.distinguishedNameToAsn1(cert.subject)
    const byteBuffer = asn1.toDer(dn)
    cAs.putInt16(byteBuffer.length())
    cAs.putBuffer(byteBuffer)
  }

  // TODO: TLS 1.2+ has a different format

  // determine length of the handshake message
  const length
    = 1 + certTypes.length()
      + 2 + cAs.length()

  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.certificate_request)
  rval.putInt24(length)
  writeVector(rval, 1, certTypes)
  writeVector(rval, 2, cAs)
  return rval
}

/**
 * Creates a ServerHelloDone message.
 *
 * @param c the connection.
 *
 * @return the ServerHelloDone byte buffer.
 */
function createServerHelloDone(c: any) {
  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.server_hello_done)
  rval.putInt24(0)

  return rval
}

/**
 * Creates a ChangeCipherSpec message.
 *
 * The change cipher spec protocol exists to signal transitions in
 * ciphering strategies. The protocol consists of a single message,
 * which is encrypted and compressed under the current (not the pending)
 * connection state. The message consists of a single byte of value 1.
 *
 * struct {
 *   enum { change_cipher_spec(1), (255) } type;
 * } ChangeCipherSpec;
 *
 * @return the ChangeCipherSpec byte buffer.
 */
tls.createChangeCipherSpec = function () {
  const rval = createBuffer()
  rval.putByte(0x01)
  return rval
}

/**
 * Creates a Finished message.
 *
 * struct {
 *   opaque verify_data[12];
 * } Finished;
 *
 * verify_data
 *   PRF(master_secret, finished_label, MD5(handshake_messages) +
 *   SHA-1(handshake_messages)) [0..11];
 *
 * finished_label
 *   For Finished messages sent by the client, the string "client
 *   finished". For Finished messages sent by the server, the
 *   string "server finished".
 *
 * handshake_messages
 *   All of the data from all handshake messages up to but not
 *   including this message. This is only data visible at the
 *   handshake layer and does not include record layer headers.
 *   This is the concatenation of all the Handshake structures as
 *   defined in 7.4 exchanged thus far.
 *
 * @param c the connection.
 *
 * @return the Finished byte buffer.
 */
tls.createFinished = function (c) {
  // generate verify_data
  let b = createBuffer()
  b.putBuffer(c.session.md5.digest())
  b.putBuffer(c.session.sha1.digest())

  // TODO: determine prf function and verify length for TLS 1.2
  const client = (c.entity === tls.ConnectionEnd.client)
  const sp = c.session.sp
  const vdl = 12
  const prf = prf_TLS1
  const label = client ? 'client finished' : 'server finished'
  b = prf(sp.master_secret, label, b.getBytes(), vdl)

  // build record fragment
  const rval = createBuffer()
  rval.putByte(tls.HandshakeType.finished)
  rval.putInt24(b.length())
  rval.putBuffer(b)
  return rval
}

/**
 * Creates a HeartbeatMessage (See RFC 6520).
 *
 * struct {
 *   HeartbeatMessageType type;
 *   uint16 payload_length;
 *   opaque payload[HeartbeatMessage.payload_length];
 *   opaque padding[padding_length];
 * } HeartbeatMessage;
 *
 * The total length of a HeartbeatMessage MUST NOT exceed 2^14 or
 * max_fragment_length when negotiated as defined in [RFC6066].
 *
 * type: The message type, either heartbeat_request or heartbeat_response.
 *
 * payload_length: The length of the payload.
 *
 * payload: The payload consists of arbitrary content.
 *
 * padding: The padding is random content that MUST be ignored by the
 *   receiver. The length of a HeartbeatMessage is TLSPlaintext.length
 *   for TLS and DTLSPlaintext.length for DTLS. Furthermore, the
 *   length of the type field is 1 byte, and the length of the
 *   payload_length is 2. Therefore, the padding_length is
 *   TLSPlaintext.length - payload_length - 3 for TLS and
 *   DTLSPlaintext.length - payload_length - 3 for DTLS. The
 *   padding_length MUST be at least 16.
 *
 * The sender of a HeartbeatMessage MUST use a random padding of at
 * least 16 bytes. The padding of a received HeartbeatMessage message
 * MUST be ignored.
 *
 * If the payload_length of a received HeartbeatMessage is too large,
 * the received HeartbeatMessage MUST be discarded silently.
 *
 * @param c the connection.
 * @param type the tls.HeartbeatMessageType.
 * @param payload the heartbeat data to send as the payload.
 * @param [payloadLength] the payload length to use, defaults to the
 *          actual payload length.
 *
 * @return the HeartbeatRequest byte buffer.
 */
function createHeartbeat(type: any, payload: any, payloadLength: any) {
  if (typeof payloadLength === 'undefined')
    payloadLength = payload.length

  // build record fragment
  const rval = createBuffer()
  rval.putByte(type) // heartbeat message type
  rval.putInt16(payloadLength) // payload length
  rval.putBytes(payload) // payload
  // padding
  const plaintextLength = rval.length()
  const paddingLength = Math.max(16, plaintextLength - payloadLength - 3)
  rval.putBytes(random.getBytes(paddingLength))
  return rval
}

/**
 * Fragments, compresses, encrypts, and queues a record for delivery.
 *
 * @param c the connection.
 * @param record the record to queue.
 */
function queue(c: any, record: any) {
  // error during record creation
  if (!record)
    return

  if (record.fragment.length() === 0) {
    if (record.type === ContentType.handshake
      || record.type === ContentType.alert
      || record.type === ContentType.change_cipher_spec) {
      // Empty handshake, alert of change cipher spec messages are not allowed per the TLS specification and should not be sent.
      return
    }
  }

  // if the record is a handshake record, update handshake hashes
  if (record.type === ContentType.handshake) {
    let bytes = record.fragment.bytes()
    c.session.md5.update(bytes)
    c.session.sha1.update(bytes)
    bytes = null
  }

  // handle record fragmentation
  let records
  if (record.fragment.length() <= tls.MaxFragment) {
    records = [record]
  }
  else {
    // fragment data as long as it is too long
    records = []
    let data = record.fragment.bytes()
    while (data.length > tls.MaxFragment) {
      records.push(createRecord(c, {
        type: record.type,
        data: createBuffer(data.slice(0, tls.MaxFragment)),
      }))
      data = data.slice(tls.MaxFragment)
    }
    // add last record
    if (data.length > 0) {
      records.push(createRecord(c, {
        type: record.type,
        data: createBuffer(data),
      }))
    }
  }

  // compress and encrypt all fragmented records
  for (let i = 0; i < records.length && !c.fail; ++i) {
    // update the record using current write state
    const rec = records[i]
    const s = c.state.current.write
    if (s.update(c, rec)) {
      // store record
      c.records.push(rec)
    }
  }
}

/**
 * Flushes all queued records to the output buffer and calls the
 * tlsDataReady() handler on the given connection.
 *
 * @param c the connection.
 *
 * @return true on success, false on failure.
 */
function flush(c: any) {
  for (let i = 0; i < c.records.length; ++i) {
    const record = c.records[i]

    // add record header and fragment
    c.tlsData.putByte(record.type)
    c.tlsData.putByte(record.version.major)
    c.tlsData.putByte(record.version.minor)
    c.tlsData.putInt16(record.fragment.length())
    c.tlsData.putBuffer(c.records[i].fragment)
  }
  c.records = []
  return c.tlsDataReady(c)
}

/**
 * Maps a pki.certificateError to a Alert.Description.
 *
 * @param error the error to map.
 *
 * @return the alert description.
 */
function _certErrorToAlertDesc(error: any) {
  switch (error) {
    case true:
      return true
    case pki.certificateError.bad_certificate:
      return Alert.Description.bad_certificate
    case pki.certificateError.unsupported_certificate:
      return Alert.Description.unsupported_certificate
    case pki.certificateError.certificate_revoked:
      return Alert.Description.certificate_revoked
    case pki.certificateError.certificate_expired:
      return Alert.Description.certificate_expired
    case pki.certificateError.certificate_unknown:
      return Alert.Description.certificate_unknown
    case pki.certificateError.unknown_ca:
      return Alert.Description.unknown_ca
    default:
      return Alert.Description.bad_certificate
  }
}

/**
 * Maps a Alert.Description to a pki.certificateError.
 *
 * @param desc the alert description.
 *
 * @return the certificate error.
 */
function _alertDescToCertError(desc) {
  switch (desc) {
    case true:
      return true
    case Alert.Description.bad_certificate:
      return pki.certificateError.bad_certificate
    case Alert.Description.unsupported_certificate:
      return pki.certificateError.unsupported_certificate
    case Alert.Description.certificate_revoked:
      return pki.certificateError.certificate_revoked
    case Alert.Description.certificate_expired:
      return pki.certificateError.certificate_expired
    case Alert.Description.certificate_unknown:
      return pki.certificateError.certificate_unknown
    case Alert.Description.unknown_ca:
      return pki.certificateError.unknown_ca
    default:
      return pki.certificateError.bad_certificate
  }
}

/**
 * Verifies a certificate chain against the given connection's
 * Certificate Authority store.
 *
 * @param c the TLS connection.
 * @param chain the certificate chain to verify, with the root or highest
 *          authority at the end.
 *
 * @return true if successful, false if not.
 */
export function verifyCertificateChain(c: any, chain: any): any {
  try {
    // Make a copy of c.verifyOptions so that we can modify options.verify
    // without modifying c.verifyOptions.
    const options = {}
    for (const key in c.verifyOptions) {
      options[key] = c.verifyOptions[key]
    }

    options.verify = function (vfd, depth, chain) {
      // convert pki.certificateError to tls alert description
      const desc = _certErrorToAlertDesc(vfd)

      // call application callback
      let ret = c.verify(c, vfd, depth, chain)
      if (ret !== true) {
        if (typeof ret === 'object' && !Array.isArray(ret)) {
          // throw custom error
          const error = new Error('The application rejected the certificate.')
          error.send = true
          error.alert = {
            level: Alert.Level.fatal,
            description: Alert.Description.bad_certificate,
          }
          if (ret.message) {
            error.message = ret.message
          }
          if (ret.alert) {
            error.alert.description = ret.alert
          }
          throw error
        }

        // convert tls alert description to pki.certificateError
        if (ret !== vfd) {
          ret = _alertDescToCertError(ret)
        }
      }

      return ret
    }

    // verify chain
    verifyCertificateChain(c.caStore, chain, options)
  }
  catch (ex) {
    // build tls error if not already customized
    let err = ex
    if (typeof err !== 'object' || Array.isArray(err)) {
      err = {
        send: true,
        alert: {
          level: Alert.Level.fatal,
          description: _certErrorToAlertDesc(ex),
        },
      }
    }
    if (!('send' in err)) {
      err.send = true
    }
    if (!('alert' in err)) {
      err.alert = {
        level: Alert.Level.fatal,
        description: _certErrorToAlertDesc(err.error),
      }
    }

    // send error
    c.error(c, err)
  }

  return !c.fail
}

/**
 * Creates a new TLS session cache.
 *
 * @param cache optional map of session ID to cached session.
 * @param capacity the maximum size for the cache (default: 100).
 *
 * @return the new TLS session cache.
 */
tls.createSessionCache = function (cache, capacity) {
  let rval = null

  // assume input is already a session cache object
  if (cache && cache.getSession && cache.setSession && cache.order) {
    rval = cache
  }
  else {
    // create cache
    rval = {}
    rval.cache = cache || {}
    rval.capacity = Math.max(capacity || 100, 1)
    rval.order = []

    // store order for sessions, delete session overflow
    for (const key in cache) {
      if (rval.order.length <= capacity) {
        rval.order.push(key)
      }
      else {
        delete cache[key]
      }
    }

    // get a session from a session ID (or get any session)
    rval.getSession = function (sessionId) {
      let session = null
      let key = null

      // if session ID provided, use it
      if (sessionId) {
        key = util.bytesToHex(sessionId)
      }
      else if (rval.order.length > 0) {
        // get first session from cache
        key = rval.order[0]
      }

      if (key !== null && key in rval.cache) {
        // get cached session and remove from cache
        session = rval.cache[key]
        delete rval.cache[key]
        for (const i in rval.order) {
          if (rval.order[i] === key) {
            rval.order.splice(i, 1)
            break
          }
        }
      }

      return session
    }

    // set a session in the cache
    rval.setSession = function (sessionId, session) {
      // remove session from cache if at capacity
      if (rval.order.length === rval.capacity) {
        var key = rval.order.shift()
        delete rval.cache[key]
      }
      // add session to cache
      var key = util.bytesToHex(sessionId)
      rval.order.push(key)
      rval.cache[key] = session
    }
  }

  return rval
}

/**
 * Creates a new TLS connection.
 *
 * See public createConnection() docs for more details.
 *
 * @param options the options for this connection.
 *
 * @return the new TLS connection.
 */
export function createConnection(options: any): any {
  let caStore = null
  if (options.caStore) {
    // if CA store is an array, convert it to a CA store object
    if (Array.isArray(options.caStore)) {
      caStore = pki.createCaStore(options.caStore)
    }
    else {
      caStore = options.caStore
    }
  }
  else {
    // create empty CA store
    caStore = pki.createCaStore()
  }

  // setup default cipher suites
  let cipherSuites = options.cipherSuites || null
  if (cipherSuites === null) {
    cipherSuites = []
    for (const key in tls.CipherSuites) {
      cipherSuites.push(tls.CipherSuites[key])
    }
  }

  // set default entity
  const entity = (options.server || false)
    ? tls.ConnectionEnd.server
    : tls.ConnectionEnd.client

  // create session cache if requested
  const sessionCache = options.sessionCache
    ? tls.createSessionCache(options.sessionCache)
    : null

  // create TLS connection
  const c = {
    version: { major: tls.Version.major, minor: tls.Version.minor },
    entity,
    sessionId: options.sessionId,
    caStore,
    sessionCache,
    cipherSuites,
    connected: options.connected,
    virtualHost: options.virtualHost || null,
    verifyClient: options.verifyClient || false,
    verify: options.verify || function (cn, vfd, dpth, cts) { return vfd },
    verifyOptions: options.verifyOptions || {},
    getCertificate: options.getCertificate || null,
    getPrivateKey: options.getPrivateKey || null,
    getSignature: options.getSignature || null,
    input: createBuffer(),
    tlsData: createBuffer(),
    data: createBuffer(),
    tlsDataReady: options.tlsDataReady,
    dataReady: options.dataReady,
    heartbeatReceived: options.heartbeatReceived,
    closed: options.closed,
    error(c, ex) {
      // set origin if not set
      ex.origin = ex.origin
        || ((c.entity === tls.ConnectionEnd.client) ? 'client' : 'server')

      // send TLS alert
      if (ex.send) {
        queue(c, tls.createAlert(c, ex.alert))
        tls.flush(c)
      }

      // error is fatal by default
      const fatal = (ex.fatal !== false)
      if (fatal) {
        // set fail flag
        c.fail = true
      }

      // call error handler first
      options.error(c, ex)

      if (fatal) {
        // fatal error, close connection, do not clear fail
        c.close(false)
      }
    },
    deflate: options.deflate || null,
    inflate: options.inflate || null,
  }

  /**
   * Resets a closed TLS connection for reuse. Called in c.close().
   *
   * @param clearFail true to clear the fail flag (default: true).
   */
  c.reset = function (clearFail) {
    c.version = { major: tls.Version.major, minor: tls.Version.minor }
    c.record = null
    c.session = null
    c.peerCertificate = null
    c.state = {
      pending: null,
      current: null,
    }
    c.expect = (c.entity === tls.ConnectionEnd.client) ? SHE : CHE
    c.fragmented = null
    c.records = []
    c.open = false
    c.handshakes = 0
    c.handshaking = false
    c.isConnected = false
    c.fail = !(clearFail || typeof (clearFail) === 'undefined')
    c.input.clear()
    c.tlsData.clear()
    c.data.clear()
    c.state.current = createConnectionState(c)
  }

  // do initial reset of connection
  c.reset()

  /**
   * Updates the current TLS engine state based on the given record.
   *
   * @param c the TLS connection.
   * @param record the TLS record to act on.
   */
  const _update = function (c, record) {
    // get record handler (align type in table by subtracting lowest)
    const aligned = record.type - ContentType.change_cipher_spec
    const handlers = ctTable[c.entity][c.expect]
    if (aligned in handlers) {
      handlers[aligned](c, record)
    }
    else {
      // unexpected record
      tls.handleUnexpected(c, record)
    }
  }

  /**
   * Reads the record header and initializes the next record on the given
   * connection.
   *
   * @param c the TLS connection with the next record.
   *
   * @return 0 if the input data could be processed, otherwise the
   *         number of bytes required for data to be processed.
   */
  const _readRecordHeader = function (c) {
    let rval = 0

    // get input buffer and its length
    const b = c.input
    const len = b.length()

    // need at least 5 bytes to initialize a record
    if (len < 5) {
      rval = 5 - len
    }
    else {
      // enough bytes for header
      // initialize record
      c.record = {
        type: b.getByte(),
        version: {
          major: b.getByte(),
          minor: b.getByte(),
        },
        length: b.getInt16(),
        fragment: createBuffer(),
        ready: false,
      }

      // check record version
      let compatibleVersion = (c.record.version.major === c.version.major)
      if (compatibleVersion && c.session && c.session.version) {
        // session version already set, require same minor version
        compatibleVersion = (c.record.version.minor === c.version.minor)
      }
      if (!compatibleVersion) {
        c.error(c, {
          message: 'Incompatible TLS version.',
          send: true,
          alert: {
            level: Alert.Level.fatal,
            description: Alert.Description.protocol_version,
          },
        })
      }
    }

    return rval
  }

  /**
   * Reads the next record's contents and appends its message to any
   * previously fragmented message.
   *
   * @param c the TLS connection with the next record.
   *
   * @return 0 if the input data could be processed, otherwise the
   *         number of bytes required for data to be processed.
   */
  const _readRecord = function (c) {
    let rval = 0

    // ensure there is enough input data to get the entire record
    const b = c.input
    const len = b.length()
    if (len < c.record.length) {
      // not enough data yet, return how much is required
      rval = c.record.length - len
    }
    else {
      // there is enough data to parse the pending record
      // fill record fragment and compact input buffer
      c.record.fragment.putBytes(b.getBytes(c.record.length))
      b.compact()

      // update record using current read state
      const s = c.state.current.read
      if (s.update(c, c.record)) {
        // see if there is a previously fragmented message that the
        // new record's message fragment should be appended to
        if (c.fragmented !== null) {
          // if the record type matches a previously fragmented
          // record, append the record fragment to it
          if (c.fragmented.type === c.record.type) {
            // concatenate record fragments
            c.fragmented.fragment.putBuffer(c.record.fragment)
            c.record = c.fragmented
          }
          else {
            // error, invalid fragmented record
            c.error(c, {
              message: 'Invalid fragmented record.',
              send: true,
              alert: {
                level: Alert.Level.fatal,
                description:
                  Alert.Description.unexpected_message,
              },
            })
          }
        }

        // record is now ready
        c.record.ready = true
      }
    }

    return rval
  }

  /**
   * Performs a handshake using the TLS Handshake Protocol, as a client.
   *
   * This method should only be called if the connection is in client mode.
   *
   * @param sessionId the session ID to use, null to start a new one.
   */
  c.handshake = function (sessionId) {
    // error to call this in non-client mode
    if (c.entity !== tls.ConnectionEnd.client) {
      // not fatal error
      c.error(c, {
        message: 'Cannot initiate handshake as a server.',
        fatal: false,
      })
    }
    else if (c.handshaking) {
      // handshake is already in progress, fail but not fatal error
      c.error(c, {
        message: 'Handshake already in progress.',
        fatal: false,
      })
    }
    else {
      // clear fail flag on reuse
      if (c.fail && !c.open && c.handshakes === 0) {
        c.fail = false
      }

      // now handshaking
      c.handshaking = true

      // default to blank (new session)
      sessionId = sessionId || ''

      // if a session ID was specified, try to find it in the cache
      let session = null
      if (sessionId.length > 0) {
        if (c.sessionCache) {
          session = c.sessionCache.getSession(sessionId)
        }

        // matching session not found in cache, clear session ID
        if (session === null) {
          sessionId = ''
        }
      }

      // no session given, grab a session from the cache, if available
      if (sessionId.length === 0 && c.sessionCache) {
        session = c.sessionCache.getSession()
        if (session !== null) {
          sessionId = session.id
        }
      }

      // set up session
      c.session = {
        id: sessionId,
        version: null,
        cipherSuite: null,
        compressionMethod: null,
        serverCertificate: null,
        certificateRequest: null,
        clientCertificate: null,
        sp: {},
        md5: forge.md.md5.create(),
        sha1: forge.md.sha1.create(),
      }

      // use existing session information
      if (session) {
        // only update version on connection, session version not yet set
        c.version = session.version
        c.session.sp = session.sp
      }

      // generate new client random
      c.session.sp.client_random = tls.createRandom().getBytes()

      // connection now open
      c.open = true

      // send hello
      queue(c, createRecord(c, {
        type: ContentType.handshake,
        data: tls.createClientHello(c),
      }))
      tls.flush(c)
    }
  }

  /**
   * Called when TLS protocol data has been received from somewhere and should
   * be processed by the TLS engine.
   *
   * @param data the TLS protocol data, as a string, to process.
   *
   * @return 0 if the data could be processed, otherwise the number of bytes
   *         required for data to be processed.
   */
  c.process = function (data) {
    let rval = 0

    // buffer input data
    if (data) {
      c.input.putBytes(data)
    }

    // process next record if no failure, process will be called after
    // each record is handled (since handling can be asynchronous)
    if (!c.fail) {
      // reset record if ready and now empty
      if (c.record !== null
        && c.record.ready && c.record.fragment.isEmpty()) {
        c.record = null
      }

      // if there is no pending record, try to read record header
      if (c.record === null) {
        rval = _readRecordHeader(c)
      }

      // read the next record (if record not yet ready)
      if (!c.fail && c.record !== null && !c.record.ready) {
        rval = _readRecord(c)
      }

      // record ready to be handled, update engine state
      if (!c.fail && c.record !== null && c.record.ready) {
        _update(c, c.record)
      }
    }

    return rval
  }

  /**
   * Requests that application data be packaged into a TLS record. The
   * tlsDataReady handler will be called when the TLS record(s) have been
   * prepared.
   *
   * @param data the application data, as a raw 'binary' encoded string, to
   *          be sent; to send utf-16/utf-8 string data, use the return value
   *          of util.encodeUtf8(str).
   *
   * @return true on success, false on failure.
   */
  c.prepare = function (data) {
    queue(c, createRecord(c, {
      type: ContentType.application_data,
      data: createBuffer(data),
    }))
    return tls.flush(c)
  }

  /**
   * Requests that a heartbeat request be packaged into a TLS record for
   * transmission. The tlsDataReady handler will be called when TLS record(s)
   * have been prepared.
   *
   * When a heartbeat response has been received, the heartbeatReceived
   * handler will be called with the matching payload. This handler can
   * be used to clear a retransmission timer, etc.
   *
   * @param payload the heartbeat data to send as the payload in the message.
   * @param [payloadLength] the payload length to use, defaults to the
   *          actual payload length.
   *
   * @return true on success, false on failure.
   */
  c.prepareHeartbeatRequest = function (payload, payloadLength) {
    if (payload instanceof util.ByteBuffer) {
      payload = payload.bytes()
    }
    if (typeof payloadLength === 'undefined') {
      payloadLength = payload.length
    }
    c.expectedHeartbeatPayload = payload
    queue(c, createRecord(c, {
      type: ContentType.heartbeat,
      data: tls.createHeartbeat(
        tls.HeartbeatMessageType.heartbeat_request,
        payload,
        payloadLength,
      ),
    }))
    return tls.flush(c)
  }

  /**
   * Closes the connection (sends a close_notify alert).
   *
   * @param clearFail true to clear the fail flag (default: true).
   */
  c.close = function (clearFail) {
    // save session if connection didn't fail
    if (!c.fail && c.sessionCache && c.session) {
      // only need to preserve session ID, version, and security params
      const session = {
        id: c.session.id,
        version: c.session.version,
        sp: c.session.sp,
      }
      session.sp.keys = null
      c.sessionCache.setSession(session.id, session)
    }

    if (c.open) {
      // connection no longer open, clear input
      c.open = false
      c.input.clear()

      // if connected or handshaking, send an alert
      if (c.isConnected || c.handshaking) {
        c.isConnected = c.handshaking = false

        // send close_notify alert
        queue(c, tls.createAlert(c, {
          level: Alert.Level.warning,
          description: Alert.Description.close_notify,
        }))
        tls.flush(c)
      }

      // call handler
      c.closed(c)
    }

    // reset TLS connection, do not clear fail flag
    c.reset(clearFail)
  }

  return c
}

/* TLS API */
export interface TLS {
  /**
   * Creates a new connection.
   *
   * @param options the options for this connection.
   *
   * @return the new TLS connection.
   */
  createConnection: (options: any) => any

  /**
   * Creates a new server.
   *
   * @param options the options for this server.
   *
   * @return the new TLS server.
   */
  createServer: (options: any) => any

  /**
   * Creates a new client.
   *
   * @param options the options for this client.
   *
   * @return the new TLS client.
   */
  createClient: (options: any) => any
}

export const tls: TLS = {
  createConnection,
  createServer,
  createClient,
  prf_tls1: prf_TLS1, // expose prf_tls1 for testing
  hmac_sha1, // expose sha1 hmac method
  createSessionCache, // expose session cache creation
}

/**
 * Creates a new TLS connection. This does not make any assumptions about the
 * transport layer that TLS is working on top of, ie: it does not assume there
 * is a TCP/IP connection or establish one. A TLS connection is totally
 * abstracted away from the layer is runs on top of, it merely establishes a
 * secure channel between a client" and a "server".
 *
 * A TLS connection contains 4 connection states: pending read and write, and
 * current read and write.
 *
 * At initialization, the current read and write states will be null. Only once
 * the security parameters have been set and the keys have been generated can
 * the pending states be converted into current states. Current states will be
 * updated for each record processed.
 *
 * A custom certificate verify callback may be provided to check information
 * like the common name on the server's certificate. It will be called for
 * every certificate in the chain. It has the following signature:
 *
 * variable func(c, certs, index, preVerify)
 * Where:
 * c         The TLS connection
 * verified  Set to true if certificate was verified, otherwise the alert
 *           Alert.Description for why the certificate failed.
 * depth     The current index in the chain, where 0 is the server's cert.
 * certs     The certificate chain, *NOTE* if the server was anonymous then
 *           the chain will be empty.
 *
 * The function returns true on success and on failure either the appropriate
 * Alert.Description or an object with 'alert' set to the appropriate
 * Alert.Description and 'message' set to a custom error message. If true
 * is not returned then the connection will abort using, in order of
 * availability, first the returned alert description, second the preVerify
 * alert description, and lastly the default 'bad_certificate'.
 *
 * There are three callbacks that can be used to make use of client-side
 * certificates where each takes the TLS connection as the first parameter:
 *
 * getCertificate(conn, hint)
 *   The second parameter is a hint as to which certificate should be
 *   returned. If the connection entity is a client, then the hint will be
 *   the CertificateRequest message from the server that is part of the
 *   TLS protocol. If the connection entity is a server, then it will be
 *   the servername list provided via an SNI extension the ClientHello, if
 *   one was provided (empty array if not). The hint can be examined to
 *   determine which certificate to use (advanced). Most implementations
 *   will just return a certificate. The return value must be a
 *   PEM-formatted certificate or an array of PEM-formatted certificates
 *   that constitute a certificate chain, with the first in the array/chain
 *   being the client's certificate.
 * getPrivateKey(conn, certificate)
 *   The second parameter is an pki X.509 certificate object that
 *   is associated with the requested private key. The return value must
 *   be a PEM-formatted private key.
 * getSignature(conn, bytes, callback)
 *   This callback can be used instead of getPrivateKey if the private key
 *   is not directly accessible in javascript or should not be. For
 *   instance, a secure external web service could provide the signature
 *   in exchange for appropriate credentials. The second parameter is a
 *   string of bytes to be signed that are part of the TLS protocol. These
 *   bytes are used to verify that the private key for the previously
 *   provided client-side certificate is accessible to the client. The
 *   callback is a function that takes 2 parameters, the TLS connection
 *   and the RSA encrypted (signed) bytes as a string. This callback must
 *   be called once the signature is ready.
 *
 * @param options the options for this connection:
 *   server: true if the connection is server-side, false for client.
 *   sessionId: a session ID to reuse, null for a new connection.
 *   caStore: an array of certificates to trust.
 *   sessionCache: a session cache to use.
 *   cipherSuites: an optional array of cipher suites to use,
 *     see tls.CipherSuites.
 *   connected: function(conn) called when the first handshake completes.
 *   virtualHost: the virtual server name to use in a TLS SNI extension.
 *   verifyClient: true to require a client certificate in server mode,
 *     'optional' to request one, false not to (default: false).
 *   verify: a handler used to custom verify certificates in the chain.
 *   verifyOptions: an object with options for the certificate chain validation.
 *     See documentation of verifyCertificateChain for possible options.
 *     verifyOptions.verify is ignored. If you wish to specify a verify handler
 *     use the verify key.
 *   getCertificate: an optional callback used to get a certificate or
 *     a chain of certificates (as an array).
 *   getPrivateKey: an optional callback used to get a private key.
 *   getSignature: an optional callback used to get a signature.
 *   tlsDataReady: function(conn) called when TLS protocol data has been
 *     prepared and is ready to be used (typically sent over a socket
 *     connection to its destination), read from conn.tlsData buffer.
 *   dataReady: function(conn) called when application data has
 *     been parsed from a TLS record and should be consumed by the
 *     application, read from conn.data buffer.
 *   closed: function(conn) called when the connection has been closed.
 *   error: function(conn, error) called when there was an error.
 *   deflate: function(inBytes) if provided, will deflate TLS records using
 *     the deflate algorithm if the server supports it.
 *   inflate: function(inBytes) if provided, will inflate TLS records using
 *     the deflate algorithm if the server supports it.
 *
 * @return the new TLS connection.
 */
forge.tls.createConnection = tls.createConnection
