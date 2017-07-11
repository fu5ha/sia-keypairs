'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

exports.default = encode;

var _helpers = require('./helpers');

function encode(value) {
    switch (typeof value === 'undefined' ? 'undefined' : _typeof(value)) {
        case 'object':
            if (value instanceof _helpers.SiaPublicKey) {
                return new Buffer.concat([value.alg, value.key]);
            } else {
                return null;
            }
        default:
            return null;
    }
}