// @flow
import assert from 'assert'
import hashjs from 'hash.js'
import brorand from 'brorand'
import elliptic from 'elliptic'
import MerkleTree from 'mtree'
import {blake2b} from 'blakejs'
import { signatureEd25519 } from './helpers'
import {EncodePublicKey, EncodeUInt32, EncodeUInt64, Encode} from './encoding'
import type {EncodeItem} from './encoding'
const Ed25519 = elliptic.eddsa('ed25519')

export type KeyPair = {
  privateKey: Buffer,
  publicKey: Buffer
}

export type UnlockConditions = {
  timelock: ?number,
  publicKeys: Array<SiaPublicKey>,
  signaturesRequired: number
}

export type SiaPublicKey = {
  algorithm: Buffer,
  key: Buffer
}

export function hashAll (items: Array<EncodeItem>) {
  return items.reduce((encItems, item) => Buffer.concat([encItems, Encode(item)]), Buffer.from([]))
}

export function generateLeaves (conditions: UnlockConditions): Array<Buffer> {
  let leaves = []
  if (conditions.timelock) {
    leaves.push(EncodeUInt64(conditions.timelock))
  }
  conditions.publicKeys.forEach((pk) => {
    leaves.push(EncodePublicKey(pk))
  })
  leaves.push(EncodeUInt64(conditions.signaturesRequired))
  return leaves
}

export function fromEd25519PublicKey (pk: Buffer): SiaPublicKey {
  return {
    algorithm: signatureEd25519,
    key: pk
  }
}

export function fromPrivateKey (prvk: Buffer): SiaPublicKey {
  return {
    algorithm: signatureEd25519,
    key: prvk.slice(32)
  }
}

export function generateKeypair (entropy: Buffer) {
  assert(!entropy || entropy.length >= 32, 'Entropy must be at least 32 bytes')
  entropy = entropy ? entropy.slice(0, 32) : brorand(32)
  return generateKeypairDeterministic(entropy)
}

export function generateKeypairDeterministic (entropy: Buffer): KeyPair {
  assert(entropy.length === 32, 'Entropy length must be exactly 32 bytes')
  const rawPrivateKey = blake2b(entropy)
  const kp = Ed25519.keyFromSecret(rawPrivateKey)
  const publicKey = Buffer.from(kp.pubBytes())
  const privateKey = Buffer.from(kp.privBytes().concat(publicKey))
  return {privateKey, publicKey}
}

export function getUnlockHash (conditions: UnlockConditions) {
  const leaves = generateLeaves(conditions)
  const tree = new MerkleTree(leaves, blake2b)
  return tree.root()
}
