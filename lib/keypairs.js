'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.hashAll = hashAll;
exports.generateLeaves = generateLeaves;
exports.fromEd25519PublicKey = fromEd25519PublicKey;
exports.fromPrivateKey = fromPrivateKey;
exports.generateKeypair = generateKeypair;
exports.generateKeypairDeterministic = generateKeypairDeterministic;
exports.getUnlockHash = getUnlockHash;

var _assert = require('assert');

var _assert2 = _interopRequireDefault(_assert);

var _brorand = require('brorand');

var _brorand2 = _interopRequireDefault(_brorand);

var _elliptic = require('elliptic');

var _elliptic2 = _interopRequireDefault(_elliptic);

var _mtree = require('mtree');

var _mtree2 = _interopRequireDefault(_mtree);

var _blakejs = require('blakejs');

var _helpers = require('./helpers');

var _encoding = require('./encoding');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var Ed25519 = _elliptic2.default.eddsa('ed25519');
function hashAll(items) {
  return items.reduce(function (encItems, item) {
    return Buffer.concat([encItems, (0, _encoding.Encode)(item)]);
  }, Buffer.from([]));
}

function generateLeaves(conditions) {
  var leaves = [];
  if (conditions.timelock) {
    leaves.push((0, _encoding.EncodeUInt64)(conditions.timelock));
  }
  conditions.publicKeys.forEach(function (pk) {
    leaves.push((0, _encoding.EncodePublicKey)(pk));
  });
  leaves.push((0, _encoding.EncodeUInt64)(conditions.signaturesRequired));
  return leaves;
}

function fromEd25519PublicKey(pk) {
  return {
    algorithm: _helpers.signatureEd25519,
    key: pk
  };
}

function fromPrivateKey(prvk) {
  return {
    algorithm: _helpers.signatureEd25519,
    key: prvk.slice(32)
  };
}

function generateKeypair(entropy) {
  (0, _assert2.default)(!entropy || entropy.length >= 32, 'Entropy must be at least 32 bytes');
  entropy = entropy ? entropy.slice(0, 32) : (0, _brorand2.default)(32);
  return generateKeypairDeterministic(entropy);
}

function generateKeypairDeterministic(entropy) {
  (0, _assert2.default)(entropy.length === 32, 'Entropy length must be exactly 32 bytes');
  var rawPrivateKey = (0, _blakejs.blake2b)(entropy);
  var kp = Ed25519.keyFromSecret(rawPrivateKey);
  var publicKey = Buffer.from(kp.pubBytes());
  var privateKey = Buffer.from(kp.privBytes().concat(publicKey));
  return { privateKey: privateKey, publicKey: publicKey };
}

function getUnlockHash(conditions) {
  var leaves = generateLeaves(conditions);
  var tree = new _mtree2.default(leaves, _blakejs.blake2b);
  return tree.root();
}