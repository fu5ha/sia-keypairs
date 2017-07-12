// @flow
import assert from 'assert'
import brorand from 'brorand'
import elliptic from 'elliptic'
import MerkleTree from 'mtree'
import {blake2bInit, blake2bFinal} from 'blakejs'
import { signatureEd25519 } from './helpers'
import {EncodePublicKey, EncodeUInt64, Encode} from './encoding'
import type {EncodeItem} from './encoding'
const Ed25519 = elliptic.eddsa('ed25519')

export type ExtendedKeyPair = {
  privateKey: Buffer,
  publicKey: Buffer
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

function blake2bHash (input: Buffer, outlen: number = 32): Buffer {
  const view = Uint8Array.from(input)
  let ctx = blake2bInit(outlen, view)
  return Buffer.from(blake2bFinal(ctx))
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

export function generateKeypair (entropy: ?Buffer): ExtendedKeyPair {
  assert(!entropy || entropy.length >= 32, 'Entropy must be at least 32 bytes')
  entropy = entropy ? entropy.slice(0, 32) : Buffer.from(brorand(32))
  return generateKeypairDeterministic(entropy)
}

export function generateKeypairDeterministic (entropy: Buffer): ExtendedKeyPair {
  assert(entropy.length === 32, 'Entropy length must be exactly 32 bytes')
  const rawPrivateKey = blake2bHash(entropy).toString('hex')
  const kp = Ed25519.keyFromSecret(rawPrivateKey)
  const publicKey = Buffer.from(kp.pubBytes())
  const privateKey = Buffer.concat([Buffer.from(kp.privBytes()), publicKey])
  return {privateKey, publicKey}
}

export function getUnlockHash (conditions: UnlockConditions) {
  const leaves = generateLeaves(conditions)
  const tree = new MerkleTree(leaves, blake2bHash)
  return tree.root()
}
