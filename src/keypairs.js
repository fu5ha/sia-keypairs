import assert from 'assert'
import hashjs from 'hash.js'
import brorand from 'brorand'
import elliptic from 'elliptic'
import MerkleTree from 'mtree'
import {blake2b} from 'blakejs'
import { signatureEd25519 } from './helpers'
import encoding from './encoding'
const Ed25519 = elliptic.eddsa('ed25519')

function sha512 (m) {
  return hashjs.sha512().update(m).digest().slice(0, 32)
}

export function hashAll () {
  assert(arguments.length >= 2, 'Must pass two or more items')
  const items = [].slice.call(arguments)
  return items.reduce((encItems, item) => Buffer.concat([encItems, encoding.Marshal(item)]), null)
}

export function KeyPair (prv, pub) {
  this.private = prv
  this.public = pub
}

export function UnlockConditions (tl, keys, sigsRequired) {
  this.timelock = tl
  this.publicKeys = keys
  this.signaturesRequired = sigsRequired
}

UnlockConditions.prototype.generateLeaves = function () {
  let leaves = []
  leaves.push(encoding.Marshal(this.timelock, 'uint64'))
  this.publicKeys.forEach(function (pk) {
    leaves.push(encoding.Marshal(pk))
  }, this)
  leaves.push(encoding.Marshal(this.signaturesRequired, 'uint64'))
}

export function SiaPublicKey (alg, pk) {
  this.algorithm = alg
  this.key = pk
}

SiaPublicKey.prototype.fromEd25519PublicKey = function (pk) {
  return new SiaPublicKey(signatureEd25519, pk)
}

export function fromPrivateKey (prvk) {
  return new SiaPublicKey(signatureEd25519, prvk.slice(32))
}

export function generateKeypair (entropy) {
  assert(!entropy || entropy.length >= 32, 'Entropy must be at least 32 bytes')
  entropy = entropy ? entropy.slice(0, 32) : brorand(32)
  return generateKeypairDeterministic(entropy)
}

export function generateKeypairDeterministic (entropy) {
  assert(entropy.length === 32, 'Entropy length must be exactly 32 bytes')
  const rawPrivateKey = sha512(entropy)
  const kp = Ed25519.keyFromSecret(rawPrivateKey)
  const publicKey = Buffer.from(kp.pubBytes())
  const privateKey = Buffer.from(kp.privBytes().concat(publicKey))
  return new KeyPair(privateKey, publicKey)
}

export function getUnlockHash (conditions) {
  assert(conditions instanceof UnlockConditions, 'invalid unlock conditions')
  const leaves = conditions.generateLeaves()
  const tree = new MerkleTree(leaves, blake2b)
  return tree.root()
}
