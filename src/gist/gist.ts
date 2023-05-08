import { BinSMT } from '../state/sparse-merkle-tree/bin-smt.js';
import { getZidenParams } from '../global.js';
import { SMTDb } from '../db/index.js';
import { bitsToNum } from '../utils.js';

interface GistProof {
  readonly gistRoot: BigInt;
  readonly gistMtp: Array<BigInt>;
  readonly gistMtpAuxHi: BigInt;
  readonly gistMtpAuxHv: BigInt;
  readonly gistMtpNoAux: BigInt;
}

export class Gist {
  private _gistTree: BinSMT;
  private _gistDepth: number;

  constructor(gistTree: BinSMT, gistDepth: number) {
    this._gistTree = gistTree;
    this._gistDepth = gistDepth;
  }

  static async generateGist(gistDb: SMTDb, gistDepth: number = 64): Promise<Gist> {
    const F = getZidenParams().F;
    let gistTree: BinSMT;

    gistTree = new BinSMT(gistDb, F.zero, gistDepth);
    return new Gist(gistTree, gistDepth);
  }

  async insertGist(Hi: Buffer, Hv: Buffer) {
    const F = getZidenParams().F;
    //await setupParams();
    const HvNum = bitsToNum(Hv);
    await this._gistTree.insert(F.toObject(getZidenParams().hasher([Hi])), HvNum);
  }

  /**
   * Generate Gist Exist Proof for a claim Gist tree
   * @param {ArrayLike<number>} gistHi
   * @returns {Promise<GistProof>} claim exist proof
   */
  async generateGistProof(gistHi: BigInt): Promise<GistProof> {
    const F = getZidenParams().F;
    const res = await this._gistTree.find(F.e(gistHi));
    if (!res.found) {
      throw new Error('Gist is not inserted to the gist tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
    this._gistDepth;
    while (siblings.length < this._gistDepth * 2) siblings.push(BigInt(0));
    return {
      gistMtp: siblings,
      gistRoot: F.toObject(this._gistTree.root),
      gistMtpAuxHi: gistHi,
      gistMtpAuxHv: F.toObject(res.foundValue!),
      gistMtpNoAux: res.isOld0 ? BigInt(1) : BigInt(0),
    };
  }
}
