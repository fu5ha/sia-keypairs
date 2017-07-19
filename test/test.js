/* global describe, it */
const expect = require('chai').expect
const keypairs = require('../lib/keypairs')
const {EncodeUInt64, EncodeUInt32, EncodePublicKey} = require('../lib/encoding')
const fs = require('fs')

const rawFile = fs.readFileSync('./test/testVectors.json', 'utf8')
const testVectors = JSON.parse(rawFile)

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
  describe('hashBlake2B', function () {
    it('should correctly hash an input', function () {
      const buf = Buffer.from(testVectors.seedBytes, 'base64')
      const res = keypairs.hashBlake2b(buf)
      const correctRes = Buffer.from(testVectors.seedHashed)
      expect(res.toString('hex')).to.equal(correctRes.toString('hex'))
    })
  })
  describe('hashAll', function () {
    it('should correctly hash multiple inputs', function () {
      const base = Buffer.from(testVectors.seedHashed)
      for (let i = 0; i < 20; i++) {
        const res = keypairs.hashAll([{val: base, type: 'buffer'}, {val: i, type: 'uint64'}])
        const correctRes = Buffer.from(testVectors.derivedAddresses[i].seed)
        expect(res.toString('hex')).to.equal(correctRes.toString('hex'))
      }
    })
  })
  describe('generateKeypairDeterministic', function () {
    it('should correctly generate key pairs from seeds', function () {
      const base = Buffer.from(testVectors.seedHashed)
      for (let i = 0; i < 20; i++) {
        const seed = keypairs.hashAll([{val: base, type: 'buffer'}, {val: i, type: 'uint64'}])
        const res = keypairs.generateKeypairDeterministic(seed)
        const correctSK = Buffer.from(testVectors.derivedAddresses[i].esk)
        const correctPK = Buffer.from(testVectors.derivedAddresses[i].epk)
        expect(res.secretKey.toString('hex')).to.deep.equal(correctSK.toString('hex'))
        expect(res.publicKey.toString('hex')).to.deep.equal(correctPK.toString('hex'))
      }
    })
  })
  describe('getUnlockHash', function () {
    it('should get correct UnlockHash from UnlockConditions', function () {
      for (let i = 0; i < 20; i++) {
        const add = testVectors.derivedAddresses[i]
        const uc = {
          publicKeys: [keypairs.fromEd25519PublicKey(Buffer.from(add.epk))],
          signaturesRequired: 1
        }
        const res = keypairs.getUnlockHash(uc)
        const correctRes = add.address
        expect(res).to.equal(correctRes)
      }
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
