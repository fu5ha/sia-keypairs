// @flow
import type {SiaPublicKey} from './keypairs'

export type EncodeType = 'publickey' |
                         'uint32' |
                         'uint64'

export type EncodeItem = {
  val: any,
  type: EncodeType
}

export function Encode (item: EncodeItem): Buffer {
  const {val, type} = item
  switch (type) {
    case 'publickey':
      return EncodePublicKey(val)
    case 'uint64':
      return EncodeUInt64(val)
    case 'uint32':
      return EncodeUInt32(val)
    default:
      throw new Error('tried to encode not recognized type')
  }
}
export function EncodePublicKey (val: SiaPublicKey): Buffer {
  return Buffer.concat([val.algorithm, val.key])
}

export function EncodeUInt64 (val: number): Buffer {
  let buf = Buffer.alloc(8)
  buf.writeUInt32LE(val, 0)
  return buf
}

export function EncodeUInt32 (val: number): Buffer {
  let buf = Buffer.alloc(4)
  buf.writeUInt32LE(val, 0)
  return buf
}
