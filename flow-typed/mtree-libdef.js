declare module 'mtree' {
  declare class MerkleTree {
    constructor(leaves: Array<any>, hasher: (val: any) => Uint8Array | Buffer): MerkleTree;
    root(): Uint8Array | Buffer
  }
  declare module.exports: Class<MerkleTree>
}
