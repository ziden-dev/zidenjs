import { SMTDb } from '../db/index.js';
import { Hash0, Hash1, Hasher, SnarkField } from 'src/global.js';
import { Entry } from '../claim/entry.js';
import { idenState, IDGenesisFromIdenState } from '../claim/id.js';
import { numToBits, bitsToNum } from '../utils.js';
import { SMT } from './smt.js';

interface MTP {
  readonly enabled: number;
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

interface ClaimFullExistsProof {
  readonly claimMTP: Array<BigInt>;
  readonly claimsTreeRoot: BigInt;
  readonly revTreeRoot: BigInt;
  readonly rootsTreeRoot: BigInt;
  readonly state: BigInt;
}

interface ClaimNotRevokedProof {
  readonly claimNonRevMTP: Array<BigInt>;
  readonly treeRoot: BigInt;
  readonly auxHi: number | BigInt;
  readonly auxHv: number | BigInt;
  readonly noAux: number | BigInt;
}

interface ClaimFullNotRevokedProof {
  readonly claimNonRevMTP: Array<BigInt>;
  readonly claimNonRevAuxHi: number | BigInt;
  readonly claimNonRevAuxHv: number | BigInt;
  readonly claimNonRevNoAux: number | BigInt;
  readonly revTreeRoot: BigInt;
  readonly claimsTreeRoot: BigInt;
  readonly rootsTreeRoot: BigInt;
  readonly state: BigInt;
}

interface ProofForClaim {
  readonly state: BigInt;
  readonly id: BigInt;
  readonly claimsTreeRoot: BigInt;
  readonly claimMTP: Array<BigInt>;
  readonly revTreeRoot: BigInt;
  readonly claimNonRevMTP: Array<BigInt>;
  readonly claimNonRevNoAux: number | BigInt;
  readonly claimNonRevAuxHi: number | BigInt;
  readonly claimNonRevAuxHv: number | BigInt;
  readonly rootsTreeRoot: BigInt;
}

export class Trees {
  _userID: Buffer;
  _claimsTree: SMT;
  _revocationTree: SMT;
  _rootsTree: SMT;
  _rootsVersion: number;
  _revocationNonce: number;
  _depth: number;
  _hasher: Hasher;
  _F: SnarkField;

  constructor(
    claimsTree: SMT,
    revocationTree: SMT,
    rootsTree: SMT,
    rootsVersion: number,
    revocationNonce: number,
    userID: Buffer,
    depth: number,
    hasher: Hasher,
    F: SnarkField
  ) {
    this._userID = userID;
    this._claimsTree = claimsTree;
    this._revocationTree = revocationTree;
    this._rootsTree = rootsTree;
    this._rootsVersion = rootsVersion;
    this._revocationNonce = revocationNonce;
    this._depth = depth;
    this._hasher = hasher;
    this._F = F;
  }

  get userID() {
    return this._userID;
  }

  get claimsTree() {
    return this._claimsTree;
  }

  get revocationTree() {
    return this._revocationTree;
  }

  get rootsTree() {
    return this._rootsTree;
  }

  get rootsVersion() {
    return this._rootsVersion;
  }

  get revocationNonce() {
    return this._revocationNonce;
  }

  get hasher() {
    return this._hasher;
  }

  get F() {
    return this._F;
  }

  /**
   * Generate iden state from auth claims
   * @param {Array<Entry>} authClaims list of auth claims to add to claim tree
   * @param {SnarkField} F
   * @param {Hash0} hash0
   * @param {Hash1} hash1
   * @param {Hasher} hasher
   * @param {SMTDb} claimsDb database for claims tree
   * @param {SMTDb} revocationDb database for revocation tree
   * @param {SMTDb} rootsDb database for roots tree
   * @param {Buffer} type 2 bytes of ID type
   * @returns {Promise<Trees>}
   */
  static async generateID(
    F: SnarkField,
    hash0: Hash0,
    hash1: Hash1,
    hasher: Hasher,
    authClaims: Array<Entry>,
    claimsDb: SMTDb,
    revocationDb: SMTDb,
    rootsDb: SMTDb,
    type: Buffer,
    depth = 32
  ): Promise<Trees> {
    const claimsTree = new SMT(claimsDb, F.zero, hash0, hash1, F, depth);
    const revocationTree = new SMT(revocationDb, F.zero, hash0, hash1, F, depth);
    const rootsTree = new SMT(rootsDb, F.zero, hash0, hash1, F, depth);

    for (let i = 0; i < authClaims.length; i++) {
      const claim = authClaims[i];
      claim.setRevocationNonce(BigInt(i));
      const hi = claim.hiRaw(hasher);
      const hv = claim.hvRaw(hasher);
      await claimsTree.insert(hi, hv);
    }

    const idState = numToBits(
      F.toObject(
        idenState(hasher, F.toObject(claimsTree.root), F.toObject(revocationTree.root), F.toObject(rootsTree.root))
      ),
      32
    );
    const userID = IDGenesisFromIdenState(idState, type);
    return new Trees(claimsTree, revocationTree, rootsTree, 0, authClaims.length, userID, depth, hasher, F);
  }

  /**
   * Insert new claim to claim tree
   * @param {Entry} claim claim to insert
   * @param {number} maxAttempTimes maximum number of inserting attempts (in case leaves have the same index)
   * @returns {Promise<Entry>} inserted claim
   */
  async insertClaim(claim: Entry, maxAttempTimes: number = 100): Promise<Entry> {
    claim.setRevocationNonce(BigInt(this._revocationNonce));
    let insertingResult;
    let triedCount = 0;
    let seed = BigInt(0);
    while (true) {
      try {
        claim.setClaimSeed(seed);
        const hi = claim.hiRaw(this._hasher);
        const hv = claim.hvRaw(this._hasher);
        insertingResult = await this._claimsTree.insert(hi, hv);
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
    await this._rootsTree.insert(this._F.e(this._rootsVersion), insertingResult.newRoot);
    this._rootsVersion++;
    return claim;
  }

  /**
   * Revoke a claim
   * @param {BigInt} revNonce claim to revoke
   */
  async revokeClaim(revNonce: BigInt) {
    await this._revocationTree.insert(this._F.e(revNonce), this._F.zero);
  }

  /**
   * Return identity State from 3 roots
   * @returns {BigInt} identity state
   */
  getIdenState(): BigInt {
    const idState = this._F.toObject(
      idenState(
        this._hasher,
        this._F.toObject(this._claimsTree.root),
        this._F.toObject(this._revocationTree.root),
        this._F.toObject(this._rootsTree.root)
      )
    );
    return idState;
  }
  /**
   * Generate Inclusion Proof for a claim in claim tree
   * @param {ArrayLike<number>} claimHi
   * @returns {Promise<MTP>} inclustion proof
   */
  async generateInclusionProof(claimHi: ArrayLike<number>): Promise<MTP> {
    const res = await this._claimsTree.find(claimHi);
    if (!res.found) {
      throw new Error('claim is not inserted to claim tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(this._F.toObject(res.siblings[i]));
    while (siblings.length < this._depth) siblings.push(BigInt(0));
    return {
      enabled: 1,
      fnc: 0,
      root: this._F.toObject(this._claimsTree.root),
      siblings: siblings,
      oldKey: 0,
      oldValue: 0,
      isOld0: 0,
      key: this._F.toObject(claimHi),
      value: this._F.toObject(res.foundValue!),
    };
  }

  /**
   * Generate Inclusion Proof for a claim in revocation tree
   * @param {BigInt} revocationNonce
   * @returns {Promise<MTP>} exclusion proof
   */
  async generateExclusionProof(revocationNonce: BigInt): Promise<MTP> {
    const res = await this._revocationTree.find(this._F.e(revocationNonce));

    if (res.found) {
      throw new Error('claim is revoked');
    }

    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(this._F.toObject(res.siblings[i]));
    while (siblings.length < this._depth) siblings.push(BigInt(0));

    return {
      enabled: 1,
      fnc: 1,
      root: this._F.toObject(this._revocationTree.root),
      siblings: siblings,
      oldKey: res.isOld0 ? 0 : this._F.toObject(res.notFoundKey!),
      oldValue: res.isOld0 ? 0 : this._F.toObject(res.notFoundValue!),
      isOld0: res.isOld0 ? 1 : 0,
      key: revocationNonce,
      value: 0,
    };
  }

  /**
   * Generate Claim Exist Proof for a claim in claim tree
   * @param {ArrayLike<number>} claimHi
   * @returns {Promise<ClaimExistsProof>} claim exist proof
   */
  async generateClaimExistsProof(claimHi: ArrayLike<number>): Promise<ClaimExistsProof> {
    const res = await this._claimsTree.find(claimHi);
    if (!res.found) {
      throw new Error('claim is not inserted to claim tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(this._F.toObject(res.siblings[i]));
    while (siblings.length < this._depth) siblings.push(BigInt(0));
    return {
      claimMTP: siblings,
      treeRoot: this._F.toObject(this._claimsTree.root),
    };
  }

  /**
   * Generate Claim Full Exist Proof for a claim in claim tree (include claim exist proof ,all roots, and state)
   * @param {ArrayLike<number>} claimHi
   * @returns {Promise<ClaimFullExistsProof>} full claim exist proof
   */
  async generateClaimFullExistsProof(claimHi: ArrayLike<number>): Promise<ClaimFullExistsProof> {
    const claimExistProof = await this.generateClaimExistsProof(claimHi);
    return {
      claimMTP: claimExistProof.claimMTP,
      claimsTreeRoot: claimExistProof.treeRoot,
      revTreeRoot: this._F.toObject(this._revocationTree.root),
      rootsTreeRoot: this._F.toObject(this._rootsTree.root),
      state: this.getIdenState(),
    };
  }

  /**
   * Generate Claim Not Revoked Proof for a claim in revocation tree
   * @param {BigInt} revocationNonce
   * @returns {Promise<ClaimNotRevokedProof>} claim not revoked proof
   */
  async generateClaimNotRevokedProof(revocationNonce: BigInt): Promise<ClaimNotRevokedProof> {
    const res = await this.generateExclusionProof(revocationNonce);
    return {
      claimNonRevMTP: res.siblings,
      treeRoot: res.root,
      auxHi: res.oldKey,
      auxHv: res.oldValue,
      noAux: res.isOld0,
    };
  }

  /**
   * Generate Claim Full Not Revoked Proof for a claim in claim tree (include claim not revoked proof ,all roots, and state)
   * @param {BigInt} revocationNonce
   * @returns {Promise<ClaimFullNotRevokedProof>} full claim not revoked proof
   */
  async generateClaimFullNotRevokedProof(revocationNonce: BigInt): Promise<ClaimFullNotRevokedProof> {
    const claimNonRevProof = await this.generateClaimNotRevokedProof(revocationNonce);
    return {
      claimNonRevMTP: claimNonRevProof.claimNonRevMTP,
      claimNonRevAuxHi: claimNonRevProof.auxHi,
      claimNonRevAuxHv: claimNonRevProof.auxHv,
      claimNonRevNoAux: claimNonRevProof.noAux,
      revTreeRoot: claimNonRevProof.treeRoot,
      claimsTreeRoot: this._F.toObject(this._claimsTree.root),
      rootsTreeRoot: this._F.toObject(this._rootsTree.root),
      state: this.getIdenState(),
    };
  }

  /**
   * Generate ID Ownership by Signature Proof for a claim in revocation tree
   * @param {ArrayLike<number>} claimHi
   * @param {BigInt} revocationNonce
   * @returns {Promise<ProofForClaim>} ID Ownership by Signature proof
   */
  async generateProofForClaim(claimHi: ArrayLike<number>, revocationNonce: BigInt): Promise<ProofForClaim> {
    // signal input userState;

    // signal input userClaimsTreeRoot;
    // signal input userAuthClaimMtp[nLevels];
    // signal input userAuthClaim[8];

    // signal input userRevTreeRoot;
    //   signal input userAuthClaimNonRevMtp[nLevels];
    //   signal input userAuthClaimNonRevMtpNoAux;
    //   signal input userAuthClaimNonRevMtpAuxHi;
    //   signal input userAuthClaimNonRevMtpAuxHv;

    // signal input userRootsTreeRoot;

    const state = this.getIdenState();
    const id = bitsToNum(this._userID);
    const claimExistProof = await this.generateClaimExistsProof(claimHi);
    const claimNonRevProof = await this.generateClaimNotRevokedProof(revocationNonce);
    return {
      state,
      id,

      claimsTreeRoot: claimExistProof.treeRoot,
      claimMTP: claimExistProof.claimMTP,
      revTreeRoot: claimNonRevProof.treeRoot,
      claimNonRevMTP: claimNonRevProof.claimNonRevMTP,
      claimNonRevNoAux: claimNonRevProof.noAux,
      claimNonRevAuxHi: claimNonRevProof.auxHi,
      claimNonRevAuxHv: claimNonRevProof.auxHv,

      rootsTreeRoot: this._F.toObject(this._rootsTree.root),
    };
  }
}
