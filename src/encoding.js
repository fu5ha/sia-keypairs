import {SiaPublicKey} from './keypairs'

export default {
  Marshal
}

export function Marshal (val) {
  switch (typeof val) {
    case 'object':
      return encodeObject(val)
    case 'number':
      return encodeNumber(val, arguments[1])
    default:
      return null
  }
}

function encodeObject (val) {
  if (val instanceof SiaPublicKey) {
    return Buffer.concat([val.alg, val.key])
  } else {
    return null
  }
}

function encodeNumber (val, type) {
  let buf
  switch (type) {
    case 'uint64':
      buf = Buffer.alloc(8)
      buf.writeUInt32LE(val, 0)
      return buf
    case 'uint32':
      buf = Buffer.alloc(4)
      buf.writeUInt32LE(val, 0)
      return buf
    default:
      return null
  }
}
