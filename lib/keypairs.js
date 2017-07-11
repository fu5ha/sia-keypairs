'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.KeyPair = KeyPair;
exports.UnlockConditions = UnlockConditions;
exports.SiaPublicKey = SiaPublicKey;
exports.generateKeypair = generateKeypair;
exports.generateKeypairDeterministic = generateKeypairDeterministic;
exports.getUnlockHash = getUnlockHash;

var _assert = require('assert');

var _assert2 = _interopRequireDefault(_assert);

var _hash = require('hash.js');

var _hash2 = _interopRequireDefault(_hash);

var _brorand = require('brorand');

var _brorand2 = _interopRequireDefault(_brorand);

var _elliptic = require('elliptic');

var _elliptic2 = _interopRequireDefault(_elliptic);

var _mtree = require('mtree');

var _mtree2 = _interopRequireDefault(_mtree);

var _blakejs = require('blakejs');

var _helpers = require('./helpers');

var _encode = require('./encode');

var _encode2 = _interopRequireDefault(_encode);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var Ed25519 = _elliptic2.default.eddsa('ed25519');

function hash(m) {
    return _hash2.default.sha512().update(m).digest().slice(0, 32);
}

function KeyPair(prv, pub) {
    this.private = prv;
    this.public = pub;
}

function UnlockConditions(tl, keys, sigsRequired) {
    this.timelock = tl;
    this.publicKeys = keys;
    this.signaturesRequired = sigsRequired;
}

UnlockConditions.prototype.generateLeaves = function () {
    var leaves = [];
    leaves.push((0, _encode2.default)(this.timelock));
    this.publicKeys.forEach(function (pk) {
        leaves.push((0, _encode2.default)(pk));
    }, this);
    leaves.push((0, _encode2.default)(this.signaturesRequired));
};

function SiaPublicKey(alg, pk) {
    this.algorithm = alg;
    this.key = pk;
}

SiaPublicKey.prototype.fromEd25519PublicKey = function (pk) {
    return new SiaPublicKey(_helpers.signatureEd25519, pk);
};

function generateKeypair(entropy) {
    (0, _assert2.default)(!entropy || entropy.length >= 32, 'Entropy must be at least 32 bytes');
    entropy = entropy ? entropy.slice(0, 32) : (0, _brorand2.default)(32);
}

function generateKeypairDeterministic(entropy) {
    (0, _assert2.default)(!entropy || entropy.length == 32, 'Entropy length must be at least 32 bytes');
    entropy = entropy ? entropy.slice(0, 32) : (0, _brorand2.default)(32);
    var privateKey = hash(entropy);
    var publicKey = Ed25519.keyFromSecret(privateKey).pubBytes();
    return new KeyPair(privateKey, publicKey);
}

function getUnlockHash(conditions) {
    (0, _assert2.default)(conditions instanceof UnlockConditions, 'invalid unlock conditions');
    var leaves = conditions.generateLeaves();
    var tree = new _mtree2.default(leaves, _blakejs.blake2b);
    return tree.root();
}