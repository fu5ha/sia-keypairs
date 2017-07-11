'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

exports.Marshal = Marshal;

var _helpers = require('./helpers');

exports.default = {
  Marshal: Marshal
};
function Marshal(val) {
  switch (typeof val === 'undefined' ? 'undefined' : _typeof(val)) {
    case 'object':
      return encodeObject(val);
    case 'number':
      return encodeNumber(val, arguments[1]);
    default:
      return null;
  }
}

function encodeObject(val) {
  if (val instanceof _helpers.SiaPublicKey) {
    return Buffer.concat([val.alg, val.key]);
  } else {
    return null;
  }
}

function encodeNumber(val, type) {
  var buf = void 0;
  switch (type) {
    case 'uint64':
      buf = Buffer.alloc(8);
      buf.writeUInt32LE(val, 0);
      return buf;
    case 'uint32':
      buf = Buffer.alloc(4);
      buf.writeUInt32LE(val, 0);
      return buf;
    default:
      return null;
  }
}