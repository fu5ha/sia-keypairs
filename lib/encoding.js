'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Encode = Encode;
exports.EncodePublicKey = EncodePublicKey;
exports.EncodeUInt64 = EncodeUInt64;
exports.EncodeUInt32 = EncodeUInt32;
function Encode(item) {
  var val = item.val,
      type = item.type;

  switch (type) {
    case 'publickey':
      return EncodePublicKey(val);
    case 'uint64':
      return EncodeUInt64(val);
    case 'uint32':
      return EncodeUInt32(val);
    default:
      throw new Error("tried to encode not recognized type");
  }
}
function EncodePublicKey(val) {
  return Buffer.concat([val.algorithm, val.key]);
}

function EncodeUInt64(val) {
  var buf = Buffer.alloc(8);
  buf.writeUInt32LE(val, 0);
  return buf;
}

function EncodeUInt32(val) {
  var buf = Buffer.alloc(4);
  buf.writeUInt32LE(val, 0);
  return buf;
}