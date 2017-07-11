import assert from 'assert'
import hashjs from 'hash.js'
import brorand from 'brorand'
import elliptic from 'elliptic'
import MerkleTree from 'mtree'
import {blake2b} from 'blakejs'
import { signatureEd25519 } from './helpers'
import encode from './encode'
const Ed25519 = elliptic.eddsa('ed25519')

function hash(m) {
    return hashjs.sha512().update(m).digest().slice(0,32)
}

export function KeyPair(prv, pub) {
    this.private = prv
    this.public = pub
}

export function UnlockConditions(tl, keys, sigsRequired) {
    this.timelock = tl
    this.publicKeys = keys
    this.signaturesRequired = sigsRequired
}

UnlockConditions.prototype.generateLeaves = function () {
    let leaves = []
    leaves.push(encode(this.timelock))
    this.publicKeys.forEach(function(pk) {
        leaves.push(encode(pk))
    }, this);
    leaves.push(encode(this.signaturesRequired))
}

export function SiaPublicKey(alg, pk) {
    this.algorithm = alg
    this.key = pk
}

SiaPublicKey.prototype.fromEd25519PublicKey = function(pk) {
    return new SiaPublicKey(signatureEd25519, pk)
}

export function generateKeypair(entropy) {
    assert(!entropy || entropy.length >= 32, 'Entropy must be at least 32 bytes')
    entropy = entropy ? entropy.slice(0,32) : brorand(32)
}

export function generateKeypairDeterministic(entropy) {
    assert(!entropy || entropy.length == 32, 'Entropy length must be at least 32 bytes')
    entropy = entropy ? entropy.slice(0,32) : brorand(32)
    const privateKey = hash(entropy)
    const publicKey = Ed25519.keyFromSecret(privateKey).pubBytes()
    return new KeyPair(privateKey, publicKey)
}

export function getUnlockHash(conditions) {
    assert(conditions instanceof UnlockConditions, 'invalid unlock conditions')
    const leaves = conditions.generateLeaves()
    const tree = new MerkleTree(leaves, blake2b)
    return tree.root()
}