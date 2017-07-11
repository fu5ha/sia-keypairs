import {SiaPublicKey} from './helpers'
export default function encode( value ) {
    switch (typeof value) {
        case 'object':
            if (value instanceof SiaPublicKey) {
                return new Buffer.concat([value.alg, value.key])
            } else {
                return null
            }
        default:
            return null
    }
}