import { describe, it } from 'bun:test'

const ASSERT = require('node:assert')
const RANDOM = require('../../lib/random')
const UTIL = require('../../lib/util');

(function () {
  describe('random', () => {
    it('should generate 10 random bytes', () => {
      const random = RANDOM.createInstance()
      random.getBytes(16)
      random.getBytes(24)
      random.getBytes(32)

      const b = random.getBytes(10)
      ASSERT.equal(b.length, 10)
    })

    it('should use a synchronous seed file', () => {
      const random = RANDOM.createInstance()
      random.seedFileSync = function (needed) {
        return UTIL.fillString('a', needed)
      }
      const b = random.getBytes(10)
      ASSERT.equal(UTIL.bytesToHex(b), '80a7901a239c3e606319')
    })

    it('should use an asynchronous seed file', (done) => {
      const random = RANDOM.createInstance()
      random.seedFile = function (needed, callback) {
        callback(null, UTIL.fillString('a', needed))
      }
      random.getBytes(10, (err, b) => {
        ASSERT.equal(err, null)
        ASSERT.equal(UTIL.bytesToHex(b), '80a7901a239c3e606319')
        done()
      })
    })

    it('should collect some random bytes', () => {
      const random = RANDOM.createInstance()
      random.seedFileSync = function (needed) {
        return UTIL.fillString('a', needed)
      }
      random.collect('bbb')
      const b = random.getBytes(10)
      ASSERT.equal(UTIL.bytesToHex(b), 'ff8d213516047c94ca46')
    })
  })
})()
