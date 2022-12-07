import { SMTDb } from '../db/index.js';
import { getZidenParams } from '../global.js';
import { Entry } from '../claim/entry.js';
import { idenState, IDGenesisFromIdenState, IDType } from '../claim/id.js';
import { numToBits, bitsToNum } from '../utils.js';
import SMT, { BinSMT, FindingResult } from './sparse-merkle-tree/index.js';

interface MTP {
  readonly fnc: number;
  readonly root: BigInt;
  readonly siblings: Array<BigInt>;
  readonly oldKey: number | BigInt;
  readonly oldValue: number | BigInt;
  readonly isOld0: number | BigInt;
  readonly key: number | BigInt;
  readonly value: number | BigInt;
}

interface ClaimExistsProof {
  readonly claimMTP: Array<BigInt>;
  readonly treeRoot: BigInt;
}

interface ProofForClaim {
  readonly state: BigInt;
  readonly id: BigInt;
  readonly claimsTreeRoot: BigInt;
  readonly claimMTP: Array<BigInt>;
  readonly authTreeRoot: BigInt;
}

export class Trees {
  private _userID: Buffer;
  private _claimsTree: SMT;
  private _authTree: SMT;
  private _revocationNonce: number;
  private _authDepth: number;
  private _claimsDepth: number;

  constructor(
    claimsTree: SMT,
    authTree: SMT,
    revocationNonce: number,
    userID: Buffer,
    authDepth: number,
    claimsDepth: number
  ) {
    this._userID = userID;
    this._claimsTree = claimsTree;
    this._authTree = authTree;
    this._revocationNonce = revocationNonce;
    this._authDepth = authDepth;
    this._claimsDepth = claimsDepth;
  }

  get userID() {
    return this._userID;
  }

  get claimsTree() {
    return this._claimsTree;
  }

  get authTree() {
    return this._authTree;
  }

  get revocationNonce() {
    return this._revocationNonce;
  }

  get authDepth() {
    return this._authDepth;
  }

  get claimsDepth() {
    return this._claimsDepth;
  }
  /**
   * Generate iden state from auth claims
   * @param {Array<Entry>} authClaims list of auth claims to add to claim tree
   * @param {SMTDb} claimsDb database for claims tree
   * @param {Buffer} type 2 bytes of ID type
   * @param {number} authDepth the depth of auth tree
   * @param {number} claimsDepth the depth of claims tree
   * @returns {Promise<Trees>}
   */
  static async generateID(
    authClaims: Array<Entry>,
    claimsDb: SMTDb,
    authDb: SMTDb,
    type: Buffer = IDType.Default,
    authDepth: number = 8,
    claimsDepth: number = 32
  ): Promise<Trees> {
    const F = getZidenParams().F;
    let claimsTree: SMT, authTree: SMT;

    claimsTree = new BinSMT(claimsDb, F.zero, claimsDepth);
    authTree = new BinSMT(authDb, F.zero, authDepth);

    for (let i = 0; i < authClaims.length; i++) {
      const claim = authClaims[i];
      claim.setRevocationNonce(BigInt(i));
      const hi = claim.hiRaw();
      const hv = claim.hvRaw();
      await authTree.insert(hi, hv);
    }

    const idState = numToBits(F.toObject(idenState(F.toObject(claimsTree.root), F.toObject(authTree.root))), 32);
    const userID = IDGenesisFromIdenState(idState, type);
    return new Trees(claimsTree, authTree, authClaims.length, userID, authDepth, claimsDepth);
  }

  /**
   * Insert new claim to claim tree
   * @param {Entry} claim claim to insert
   * @param {number} maxAttempTimes maximum number of inserting attempts (in case leaves have the same index)
   * @returns {Promise<Entry>} inserted claim
   */
  async insertClaim(claim: Entry, maxAttempTimes: number = 100): Promise<Entry> {
    claim.setRevocationNonce(BigInt(this._revocationNonce));
    let triedCount = 0;
    let seed = BigInt(0);
    while (true) {
      try {
        claim.setClaimSeed(seed);
        const hi = claim.hiRaw();
        const hv = claim.hvRaw();
        await this._claimsTree.insert(hi, hv);
        break;
      } catch (err) {
        if (triedCount >= maxAttempTimes - 1) {
          throw new Error('Failed inserting caused by collision');
        }
        seed += BigInt(1);
        triedCount++;
      }
    }
    this._revocationNonce += 1;
    return claim;
  }

  /**
   * Insert new claim to claim tree
   * @param {Entry} authClaim authClaim to insert
   * @returns {Promise<Entry>} inserted claim
   */
  async insertAuthClaim(authClaim: Entry): Promise<Entry> {
    authClaim.setRevocationNonce(BigInt(this._revocationNonce));

    const hi = authClaim.hiRaw();
    const hv = authClaim.hvRaw();
    await this._authTree.insert(hi, hv);

    this._revocationNonce += 1;
    return authClaim;
  }

  /**
   * Insert a batch of claims by their his and hvs
   * @param {Array<[ArrayLike<number>, ArrayLike<number>]>} claimHiHvs claim to insert
   */
  async batchInsertClaimByHiHv(claimHiHvs: Array<[ArrayLike<number>, ArrayLike<number>]>) {
    for (let i = 0; i < claimHiHvs.length; i++) {
      await this._claimsTree.insert(claimHiHvs[i][0], claimHiHvs[i][1]);
    }
  }

  /**
   * Insert a batch of claims by their his and hvs
   * @param {Array<Entry>} authClaims auth claims to insert
   */
  async batchInsertAuthClaim(authClaims: Array<Entry>) {
    for (let i = 0; i < authClaims.length; i++) {
      await this.insertAuthClaim(authClaims[i]);
    }
  }

  /**
   * prepare new claim for inserting
   * @param {Entry} claim claim to insert
   * @param {number} maxAttempTimes maximum number of inserting attempts (in case leaves have the same index)
   * @returns {Promise<Entry>} inserted claim
   */
  async prepareClaimForInsert(claim: Entry, maxAttempTimes: number = 100): Promise<Entry> {
    claim.setRevocationNonce(BigInt(this._revocationNonce));
    let triedCount = 0;
    let seed = BigInt(0);
    while (true) {
      try {
        claim.setClaimSeed(seed);
        const hi = claim.hiRaw();
        const findingResult = await this._claimsTree.find(hi);
        if (findingResult.found) {
          throw new Error('Claim Hi already existed in claims tree');
        }
        break;
      } catch (err) {
        if (triedCount >= maxAttempTimes - 1) {
          throw new Error('Failed inserting caused by collision, please try increasing max attemp times');
        }
        seed += BigInt(1);
        triedCount++;
      }
    }
    this._revocationNonce += 1;
    return claim;
  }

  /**
   * Return identity State from 3 roots
   * @returns {BigInt} identity state
   */
  getIdenState(): BigInt {
    const idState = getZidenParams().F.toObject(
      idenState(getZidenParams().F.toObject(this._claimsTree.root), getZidenParams().F.toObject(this._authTree.root))
    );
    return idState;
  }
  /**
   * Generate Inclusion Proof for a claim
   * @param {ArrayLike<number>} claimHi
   * @param {boolean} isClaimsTree claim is in claims tree or auth tree ?
   * @returns {Promise<MTP>} inclustion proof
   */
  async generateInclusionProof(claimHi: ArrayLike<number>, isClaimsTree: boolean = true): Promise<MTP> {
    let res: FindingResult;
    if (isClaimsTree) res = await this._claimsTree.find(claimHi);
    else res = await this._authTree.find(claimHi);
    if (!res.found) {
      throw new Error('claim is not inserted to claim tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(getZidenParams().F.toObject(res.siblings[i]));
    while (siblings.length < (isClaimsTree ? this._claimsDepth : this._authDepth)) siblings.push(BigInt(0));

    return {
      fnc: 0,
      root: getZidenParams().F.toObject(isClaimsTree ? this._claimsTree.root : this._authTree.root),
      siblings: siblings,
      oldKey: 0,
      oldValue: 0,
      isOld0: 0,
      key: getZidenParams().F.toObject(claimHi),
      value: getZidenParams().F.toObject(res.foundValue!),
    };
  }

  /**
   * Generate Claim Exist Proof for a claim
   * @param {ArrayLike<number>} claimHi
   * @param {boolean} isClaimsTree claim is in claims tree or auth tree ?
   * @returns {Promise<ClaimExistsProof>} claim exist proof
   */
  async generateClaimExistsProof(claimHi: ArrayLike<number>, isClaimsTree: boolean = true): Promise<ClaimExistsProof> {
    let res: FindingResult;
    if (isClaimsTree) res = await this._claimsTree.find(claimHi);
    else res = await this._authTree.find(claimHi);
    if (!res.found) {
      throw new Error('claim is not inserted to the claim tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(getZidenParams().F.toObject(res.siblings[i]));
    while (siblings.length < (isClaimsTree ? this._claimsDepth : this._authDepth)) siblings.push(BigInt(0));

    return {
      claimMTP: siblings,
      treeRoot: getZidenParams().F.toObject(isClaimsTree ? this._claimsTree.root : this._authTree.root),
    };
  }

  /**
   * Generate ID Ownership by Signature Proof for a claim in claims tree
   * @param {ArrayLike<number>} claimHi
   * @returns {Promise<ProofForClaim>} ID Ownership by Signature proof
   */
  async generateProofForClaim(claimHi: ArrayLike<number>): Promise<ProofForClaim> {
    const state = this.getIdenState();
    const id = bitsToNum(this._userID);
    const claimExistProof = await this.generateClaimExistsProof(claimHi);

    return {
      state,
      id,
      claimsTreeRoot: claimExistProof.treeRoot,
      claimMTP: claimExistProof.claimMTP,
      authTreeRoot: getZidenParams().F.toObject(this._authTree.root),
    };
  }

  /**
   * Generate ID Ownership by Signature Proof for an auth claim in auth tree
   * @param {ArrayLike<number>} claimHi
   * @returns {Promise<ProofForClaim>} ID Ownership by Signature proof
   */
  async generateProofForAuthClaim(claimHi: ArrayLike<number>): Promise<ProofForClaim> {
    const state = this.getIdenState();
    const id = bitsToNum(this._userID);
    const claimExistProof = await this.generateClaimExistsProof(claimHi, false);

    return {
      state,
      id,
      claimsTreeRoot: getZidenParams().F.toObject(this._claimsTree.root),
      claimMTP: claimExistProof.claimMTP,
      authTreeRoot: getZidenParams().F.toObject(this._authTree.root),
    };
  }
}
