// @flow
declare module 'blakejs' {
  declare type Blake2bContext = {
    b: Uint8Array,
    h: Uint8Array,
    t: number,
    c: number,
    outlen: number
  }
  declare function blake2bInit(outlen: number, input: Uint8Array): Blake2bContext
  declare function blake2bFinal(ctx: Blake2bContext): Uint8Array
  declare function blake2b(input: Buffer | Uint8Array, key: ?Uint8Array, outlen: ?number): Uint8Array
  declare function blake2bUpdate (ctx: Blake2bContext, input: Uint8Array): void
}
