import { describe, it } from 'bun:test'

const ASSERT = require('node:assert')
const FORGE = require('../../lib/forge')
const MD = require('../../lib/md.all')
const PBKDF2 = require('../../lib/pbkdf2')
const UTIL = require('../../lib/util');

(function () {
  describe('pbkdf2', () => {
    it('should derive a password with hmac-sha-1 c=1', () => {
      const dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 1, 20))
      ASSERT.equal(dkHex, '0c60c80f961f0e71f3a9b524af6012062fe037a6')
    })

    it('should derive a password with hmac-sha-1 c=2', () => {
      const dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 2, 20))
      ASSERT.equal(dkHex, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957')
    })

    it('should derive a password with hmac-sha-1 c=5 keylen=8', () => {
      const salt = UTIL.hexToBytes('1234567878563412')
      const dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 5, 8))
      ASSERT.equal(dkHex, 'd1daa78615f287e6')
    })

    it('should derive a utf8 password with hmac-sha-1 c=1 keylen=16', () => {
      const dkHex = UTIL.bytesToHex(PBKDF2('中', 'salt', 1, 16))
      ASSERT.equal(dkHex, '5f719aa196edc4df6b1556de503faaf3')
    })

    it('should derive a password with hmac-sha-1 c=4096', () => {
      // Note: might be too slow on old browsers
      const dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 4096, 20))
      ASSERT.equal(dkHex, '4b007901b765489abead49d926f721d065a429c1')
    })

    /*
    it('should derive a password with hmac-sha-1 c=16777216', function() {
      // Note: too slow
      var dkHex = UTIL.bytesToHex(PBKDF2('password', 'salt', 16777216, 20));
      ASSERT.equal(dkHex, 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984');
    }); */

    it('should derive a password with hmac-sha-256 c=1000', () => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      const md = MD.sha256.create()
      const dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, md))
      ASSERT.equal(dkHex, '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2')
    })

    it('should derive a password with hmac-sha-256 (passed as an algorithm identifier) c=1000', () => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      const dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, 'sha256'))
      ASSERT.equal(dkHex, '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2')
    })

    it('should derive a password with hmac-sha-512 c=1000', () => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      const md = MD.sha512.create()
      const dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, md))
      ASSERT.equal(dkHex, '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3')
    })

    it('should derive a password with hmac-sha-512 (passed as an algorithm identifier) c=1000', () => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      const dkHex = UTIL.bytesToHex(PBKDF2('password', salt, 1000, 48, 'sha512'))
      ASSERT.equal(dkHex, '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3')
    })

    it('should asynchronously derive a password with hmac-sha-1 c=1', (done) => {
      PBKDF2('password', 'salt', 1, 20, (err, dk) => {
        ASSERT.ifError(err)
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, '0c60c80f961f0e71f3a9b524af6012062fe037a6')
        done()
      })
    })

    it('should asynchronously derive a password with hmac-sha-1 c=2', (done) => {
      PBKDF2('password', 'salt', 2, 20, (err, dk) => {
        ASSERT.ifError(err)
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957')
        done()
      })
    })

    it('should asynchronously derive a password with hmac-sha-1 c=5 keylen=8', (done) => {
      const salt = UTIL.hexToBytes('1234567878563412')
      PBKDF2('password', salt, 5, 8, (err, dk) => {
        ASSERT.ifError(err)
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, 'd1daa78615f287e6')
        done()
      })
    })

    it('should asynchronously derive a password with hmac-sha-1 c=4096', (done) => {
      // Note: might be too slow on old browsers
      PBKDF2('password', 'salt', 4096, 20, (err, dk) => {
        ASSERT.ifError(err)
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, '4b007901b765489abead49d926f721d065a429c1')
        done()
      })
    })

    /*
    it('should asynchronously derive a password with hmac-sha-1 c=16777216', function(done) {
      // Note: too slow
      PBKDF2('password', 'salt', 16777216, 20, function(err, dk) {
        ASSERT.ifError(err);
        var dkHex = UTIL.bytesToHex(dk);
        ASSERT.equal(dkHex, 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984');
        done();
      });
    }); */

    it('should asynchronously derive a password with hmac-sha-256 c=1000', (done) => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      const md = MD.sha256.create()
      PBKDF2('password', salt, 1000, 48, md, (err, dk) => {
        ASSERT.ifError(err)
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2')
        done()
      })
    })

    it('should asynchronously derive a password with hmac-sha-256 (passed as an algorithm identifier) c=1000', (done) => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      PBKDF2('password', salt, 1000, 48, 'sha256', (err, dk) => {
        ASSERT.ifError(err)
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, '9da8a5f4ae605f35e82e5beac5f362df15c4255d88f738d641466a4107f9970238e768e72af29ac89a1b16ff277b31d2')
        done()
      })
    })

    it('should asynchronously derive a password with hmac-sha-512 c=1000', (done) => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      const md = MD.sha512.create()
      PBKDF2('password', salt, 1000, 48, md, (err, dk) => {
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3')
        done()
      })
    })

    it('should asynchronously derive a password with hmac-sha-512 (passed as an algorithm identifier) c=1000', (done) => {
      // Note: might be too slow on old browsers
      const salt = '4bcda0d1c689fe465c5b8a817f0ddf3d'
      PBKDF2('password', salt, 1000, 48, 'sha512', (err, dk) => {
        const dkHex = UTIL.bytesToHex(dk)
        ASSERT.equal(dkHex, '975725960aa736f721182962677291a9085c75421c38636098d904f5a96f11a485f767082b710a69f8a46bcf9eba29f3')
        done()
      })
    })

    it('should derive a password with "usePureJavaScript"', () => {
      // save
      const purejs = FORGE.options.usePureJavaScript
      // test possible native mode
      FORGE.options.usePureJavaScript = false
      const dkHex0 = UTIL.bytesToHex(PBKDF2('password', 'salt', 1024, 20))
      // test pure mode
      FORGE.options.usePureJavaScript = true
      const dkHex1 = UTIL.bytesToHex(PBKDF2('password', 'salt', 1024, 20))
      // check
      ASSERT.equal(dkHex0, 'f9d39c571d66a03c2a71a81535b0c2d0396b500a')
      ASSERT.equal(dkHex0, dkHex1)
      // restore
      FORGE.options.usePureJavaScript = purejs
    })
  })
})()
