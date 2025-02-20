const ASSERT = require('node:assert')
const forge = require('../../lib/forge')
require('../../lib/tls')
require('../../lib/aesCipherSuites')
require('../../lib/util');

(function () {
  describe('tls', () => {
    it('should test TLS 1.0 PRF', () => {
      // Note: This test vector is originally from:
      // http://www.imc.org/ietf-tls/mail-archive/msg01589.html
      // But that link is now dead.
      const secret = forge.util.createBuffer().fillWithByte(0xAB, 48).getBytes()
      const seed = forge.util.createBuffer().fillWithByte(0xCD, 64).getBytes()
      const bytes = forge.tls.prf_tls1(secret, 'PRF Testvector', seed, 104)
      const expect
        = 'd3d4d1e349b5d515044666d51de32bab258cb521'
          + 'b6b053463e354832fd976754443bcf9a296519bc'
          + '289abcbc1187e4ebd31e602353776c408aafb74c'
          + 'bc85eff69255f9788faa184cbb957a9819d84a5d'
          + '7eb006eb459d3ae8de9810454b8b2d8f1afbc655'
          + 'a8c9a013'
      ASSERT.equal(bytes.toHex(), expect)
    })

    it('should establish a TLS connection and transfer data', (done) => {
      const end = {}
      const data = {}

      createCertificate('server', data)
      createCertificate('client', data)
      data.client.connection = {}
      data.server.connection = {}

      end.client = forge.tls.createConnection({
        server: false,
        caStore: [data.server.cert],
        sessionCache: {},
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        virtualHost: 'server',
        verify(c, verified, depth, certs) {
          data.client.connection.commonName
            = certs[0].subject.getField('CN').value
          data.client.connection.certVerified = verified
          return true
        },
        connected(c) {
          c.prepare('Hello Server')
        },
        getCertificate(c, hint) {
          return data.client.cert
        },
        getPrivateKey(c, cert) {
          return data.client.privateKey
        },
        tlsDataReady(c) {
          end.server.process(c.tlsData.getBytes())
        },
        dataReady(c) {
          data.client.connection.data = c.data.getBytes()
          c.close()
        },
        closed(c) {
          ASSERT.equal(data.client.connection.commonName, 'server')
          ASSERT.equal(data.client.connection.certVerified, true)
          ASSERT.equal(data.client.connection.data, 'Hello Client')
          done()
        },
        error(c, error) {
          ASSERT.equal(error.message, undefined)
        },
      })

      end.server = forge.tls.createConnection({
        server: true,
        caStore: [data.client.cert],
        sessionCache: {},
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        connected(c) {
        },
        verifyClient: true,
        verify(c, verified, depth, certs) {
          data.server.connection.commonName
            = certs[0].subject.getField('CN').value
          data.server.connection.certVerified = verified
          return true
        },
        getCertificate(c, hint) {
          data.server.connection.certHint = hint[0]
          return data.server.cert
        },
        getPrivateKey(c, cert) {
          return data.server.privateKey
        },
        tlsDataReady(c) {
          end.client.process(c.tlsData.getBytes())
        },
        dataReady(c) {
          data.server.connection.data = c.data.getBytes()
          c.prepare('Hello Client')
          c.close()
        },
        closed(c) {
          ASSERT.equal(data.server.connection.certHint, 'server')
          ASSERT.equal(data.server.connection.commonName, 'client')
          ASSERT.equal(data.server.connection.certVerified, true)
          ASSERT.equal(data.server.connection.data, 'Hello Server')
        },
        error(c, error) {
          ASSERT.equal(error.message, undefined)
        },
      })

      end.client.handshake()

      function createCertificate(cn, data) {
        const keys = forge.pki.rsa.generateKeyPair(512)
        const cert = forge.pki.createCertificate()
        cert.publicKey = keys.publicKey
        cert.serialNumber = '01'
        cert.validity.notBefore = new Date()
        cert.validity.notAfter = new Date()
        cert.validity.notAfter.setFullYear(
          cert.validity.notBefore.getFullYear() + 1,
        )
        const attrs = [{
          name: 'commonName',
          value: cn,
        }, {
          name: 'countryName',
          value: 'US',
        }, {
          shortName: 'ST',
          value: 'Virginia',
        }, {
          name: 'localityName',
          value: 'Blacksburg',
        }, {
          name: 'organizationName',
          value: 'Test',
        }, {
          shortName: 'OU',
          value: 'Test',
        }]
        cert.setSubject(attrs)
        cert.setIssuer(attrs)
        cert.setExtensions([{
          name: 'basicConstraints',
          cA: true,
        }, {
          name: 'keyUsage',
          keyCertSign: true,
          digitalSignature: true,
          nonRepudiation: true,
          keyEncipherment: true,
          dataEncipherment: true,
        }, {
          name: 'subjectAltName',
          altNames: [{
            type: 6, // URI
            value: 'https://myuri.com/webid#me',
          }],
        }])
        cert.sign(keys.privateKey)
        data[cn] = {
          cert: forge.pki.certificateToPem(cert),
          privateKey: forge.pki.privateKeyToPem(keys.privateKey),
        }
      }
    })
  })
})()
