/* global describe, it */
const expect = require('chai').expect
const keypairs = require('../lib/keypairs')
const {EncodeUInt64, EncodeUInt32, EncodePublicKey} = require('../lib/encoding')

describe('keypairs', function () {
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

describe('encoding', function () {
  describe('EncodeUInt64(number)', function () {
    it('should encode numbers correctly', function () {
      var val = 323493
      var res = EncodeUInt64(val)
      var correctRes = Buffer.from([165, 239, 4, 0, 0, 0, 0, 0])
      expect(res).to.deep.equal(correctRes)
    })
  })

  describe('EncodeUInt32(number)', function () {
    it('should encode numbers correctly', function () {
      var val = 323493
      var res = EncodeUInt32(val)
      var correctRes = Buffer.from([165, 239, 4, 0])
      expect(res).to.deep.equal(correctRes)
    })
  })

  describe('EncodePublicKey(SiaPublicKey)', function () {
    it('should encode SiaPublicKey correctly', function () {
      var prvk = Buffer.alloc(64)
      prvk[0] = 4
      prvk[32] = 5
      var key = keypairs.fromPrivateKey(prvk)
      var res = EncodePublicKey(key)
      var correctRes = Buffer.concat([Buffer.from('ed25519'), Buffer.from(prvk.slice(32))])
      expect(res).to.deep.equal(correctRes)
    })
  })
})
