'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

exports.Encode = Encode;
exports.EncodeObject = EncodeObject;
exports.EncodeNumber = EncodeNumber;
exports.EncodePublicKey = EncodePublicKey;
exports.EncodeUInt64 = EncodeUInt64;
exports.EncodeUInt32 = EncodeUInt32;
function Encode(item) {
  var val = item.val,
      type = item.type;

  switch (typeof val === 'undefined' ? 'undefined' : _typeof(val)) {
    case 'object':
      return EncodeObject(val, type);
    case 'number':
      return EncodeNumber(val, type);
    default:
      throw new Error('tried to encode not recognized type (' + (typeof val === 'undefined' ? 'undefined' : _typeof(val)) + ')');
  }
}
function EncodeObject(val, type) {
  switch (type) {
    case 'publickey':
      return EncodePublicKey(val);
    case 'buffer':
      return val;
    default:
      throw new Error('tried to encode not recognized object type (' + type + ')');
  }
}

function EncodeNumber(val, type) {
  switch (type) {
    case 'uint64':
      return EncodeUInt64(val);
    case 'uint32':
      return EncodeUInt32(val);
    default:
      throw new Error('tried to encode not recognized number type');
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