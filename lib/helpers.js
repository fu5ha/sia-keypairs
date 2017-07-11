'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.KeyPair = KeyPair;
var signatureEd25519 = exports.signatureEd25519 = Buffer.from('ed25519');

function KeyPair(prv, pub) {
  this.private = prv;
  this.public = pub;
}