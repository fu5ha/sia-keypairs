// @flow
import assert from 'assert'
import brorand from 'brorand'
import nacl from 'tweetnacl'
import MerkleTree from 'mtree'
import { blake2b } from 'blakejs'
import { signatureEd25519 } from './helpers'
import { EncodePublicKey, EncodeUInt64, Encode } from './encoding'
import type { EncodeItem } from './encoding'

export type KeyPair = {
  secretKey: Uint8Array,
  publicKey: Uint8Array
}

export type SiaPublicKey = {
  algorithm: Buffer,
  key: Buffer
}

export type UnlockConditions = {
  timelock: ?number,
  publicKeys: Array<SiaPublicKey>,
  signaturesRequired: number
}

export function hashBlake2b (input: Buffer, outlen: number = 32): Buffer {
  const view = Uint8Array.from(input)
  return Buffer.from(blake2b(view, null, 32))
}

export function hashAll (items: Array<EncodeItem>): Buffer {
  return hashBlake2b(items.reduce((encodedItems, item) => Buffer.concat([encodedItems, Encode(item)]), Buffer.from([])))
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

export function generateKeypair (entropy: ?Buffer): KeyPair {
  assert(!entropy || entropy.length >= 32, 'Entropy must be at least 32 bytes')
  entropy = entropy ? entropy.slice(0, 32) : Buffer.from(brorand(32))
  return generateKeypairDeterministic(entropy)
}

export function generateKeypairDeterministic (entropy: Buffer): KeyPair {
  assert(entropy.length === 32, 'Entropy length must be exactly 32 bytes')
  const kp = nacl.sign.keyPair.fromSeed(Uint8Array.from(entropy))
  return {secretKey: Buffer.from(kp.secretKey), publicKey: Buffer.from(kp.publicKey)}
}

export function getUnlockHash (conditions: UnlockConditions): string {
  const leaves = generateLeaves(conditions)
  const tree = new MerkleTree(leaves, hashBlake2b)
  return Buffer.from(tree.root()).toString('hex')
}
