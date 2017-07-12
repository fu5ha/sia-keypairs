// @flow
declare module 'elliptic' {
  declare class EDDSA {
    keyFromSecret(secret: string): KeyPair;
  }

  declare class KeyPair {
    constructor (eddsa: EDDSA, params: {pub: ?string, secret: ?string}): KeyPair;
    fromSecret(eddsa: EDDSA, secret: string): KeyPair;
    pubBytes(): Uint8Array;
    privBytes(): Uint8Array;
  }

  declare type Curve = {
    type: string,
    primt: string,
    p: string,
    a: string,
    c: string,
    d: string,
    n: string,
    hash: Function,
    gRed: boolean,
    g: Array<string>
  }
  declare module.exports: {
    eddsa: (curve: string) => EDDSA,
    KeyPair: KeyPair
  }
}
