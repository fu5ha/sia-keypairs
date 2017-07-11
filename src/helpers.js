export const signatureEd25519 = Buffer.from('ed25519', 'utf-8')

export function KeyPair(prv, pub) {
    this.private = prv
    this.public = pub
}
