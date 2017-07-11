/* global describe, it */
const expect = require('chai').expect
const keypairs = require('../lib/keypairs')
const encoding = require('../lib/encoding')

describe('keypairs', function () {
  describe('SiaPublicKey', function () {
    describe('fromPrivateKey', function () {
      it('should get the proper public key from extended private key', function () {
        const prvk = Buffer.alloc(64)
        prvk[0] = 4
        prvk[32] = 5
        const pubk = keypairs.fromPrivateKey(prvk)
        let correctPubk = Buffer.alloc(32)
        correctPubk[0] = 5
        expect(pubk.key).to.deep.equal(correctPubk)
      })
    })
  })
})

describe('encoding', function () {
  describe('Marshal(uint64)', function () {
    it('should encode numbers correctly', function () {
      var val = 323493
      var res = encoding.Marshal(val, 'uint64')
      var correctRes = Buffer.from([165, 239, 4, 0, 0, 0, 0, 0])
      expect(res).to.deep.equal(correctRes)
    })
  })

  describe('Marshal(uint32)', function () {
    it('should encode numbers correctly', function () {
      var val = 323493
      var res = encoding.Marshal(val, 'uint32')
      var correctRes = Buffer.from([165, 239, 4, 0])
      expect(res).to.deep.equal(correctRes)
    })
  })

  describe('Marshal(SiaPublicKey)', function () {
    it('should encode SiaPublicKey correctly', function () {
      var prvk = Buffer.alloc(64)
      prvk[0] = 4
      prvk[32] = 5
      var key = keypairs.fromPrivateKey(prvk)
      var res = encoding.Marshal(key)
      var correctRes = Buffer.from([0, 0, 0, 0, 0, 4, 239, 165])
      expect(res).to.deep.equal(correctRes)
    })
  })
})
