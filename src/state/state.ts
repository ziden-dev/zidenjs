import { SMTDb } from '../db/index.js';
import { getZidenParams } from '../global.js';
import { Entry } from '../claim/entry.js';
import { idenState, IDGenesisFromIdenState, IDType } from '../claim/id.js';
import { bitsToNum, numToBits } from '../utils.js';
import { QuinSMT } from './sparse-merkle-tree/index.js';
import { Auth } from '../index.js';
import { hashPublicKey } from './auth.js';

interface AuthExistsProof {
  readonly authMTP: Array<BigInt>;
  readonly authsRoot: BigInt;
}
interface ClaimExistsProof {
  readonly claimMTP: Array<BigInt>;
  readonly treeRoot: BigInt;
}

interface RootsMatchProof {
  readonly authsRoot: BigInt;
  readonly claimsRoot: BigInt;
  readonly authRevRoot: BigInt;
  readonly claimRevRoot: BigInt;
  readonly expectedState: BigInt;
}

interface AuthNotRevokedProof {
  readonly authHi: BigInt;
  readonly authNonRevMTP: Array<BigInt>;
  readonly authRevRoot: BigInt;
  readonly auxHi: BigInt;
  readonly auxHv: BigInt;
  readonly noAux: BigInt;
}

interface ClaimNotRevokedProof {
  readonly claimNonRevMTP: Array<BigInt>;
  readonly treeRoot: BigInt;
  readonly auxHi: BigInt;
  readonly auxHv: BigInt;
  readonly noAux: BigInt;
}

export class State {
  private _userID: Buffer;
  private _authsTree: QuinSMT;
  private _claimsTree: QuinSMT;
  private _authRevTree: QuinSMT;
  private _claimRevTree: QuinSMT;
  private _authRevNonce: number;
  private _claimRevNonce: number;
  private _authDepth: number;
  private _claimDepth: number;

  constructor(
    authsTree: QuinSMT,
    claimsTree: QuinSMT,
    authRevTree: QuinSMT,
    claimRevTree: QuinSMT,
    authRevNonce: number,
    claimRevNonce: number,
    authDepth: number,
    claimDepth: number
  ) {
    this._authsTree = authsTree;
    this._claimsTree = claimsTree;
    this._authRevTree = authRevTree;
    this._claimRevTree = claimRevTree;
    this._authRevNonce = authRevNonce;
    this._claimRevNonce = claimRevNonce;
    this._authDepth = authDepth;
    this._claimDepth = claimDepth;
    const userState = this.getIdenState();
    this._userID = IDGenesisFromIdenState(userState, IDType.Default);
  }

  get userID() {
    return this._userID;
  }

  get authsTree() {
    return this._authsTree;
  }

  get claimsTree() {
    return this._claimsTree;
  }

  get authRevTree() {
    return this._authRevTree;
  }

  get claimRevTree() {
    return this._claimRevTree;
  }

  get authRevNonce() {
    return this._authRevNonce;
  }

  get claimRevNonce() {
    return this._claimRevNonce;
  }

  get authDepth() {
    return this._authDepth;
  }

  get claimDepth() {
    return this._claimDepth;
  }

  getIdenState(): Buffer {
    const F = getZidenParams().F;
    return numToBits(
      F.toObject(
        idenState(
          F.toObject(this._authsTree.root),
          F.toObject(this._claimsTree.root),
          F.toObject(this._authRevTree.root),
          F.toObject(this._claimRevTree.root)
        )
      ),
      32
    );
  }
  /**
   * Generate iden state from auth claims
   * @param {Array<Auth>} auths list of public keys to add to claim tree
   * @param {SMTDb} authsDb database for auths tree
   * @param {SMTDb} claimsDb database for claims tree
   * @param {SMTDb} authRevDb database for auth revocation tree
   * @param {SMTDb} claimRevDb database for claim revocation tree
   * @param {number} authDepth the depth of auth and auth rev trees
   * @param {number} claimDepth the depth of claim and claim rev trees
   * @returns {Promise<State>}
   */
  static async generateState(
    auths: Array<Auth>,
    authsDb: SMTDb,
    claimsDb: SMTDb,
    authRevDb: SMTDb,
    claimRevDb: SMTDb,
    authDepth: number = 4,
    claimDepth: number = 14
  ): Promise<State> {
    const F = getZidenParams().F;
    let authsTree: QuinSMT, claimsTree: QuinSMT, authRevTree: QuinSMT, claimRevTree: QuinSMT;

    authsTree = new QuinSMT(authsDb, F.zero, authDepth);
    claimsTree = new QuinSMT(claimsDb, F.zero, claimDepth);
    authRevTree = new QuinSMT(authRevDb, F.zero, authDepth);
    claimRevTree = new QuinSMT(claimRevDb, F.zero, claimDepth);

    for (let i = 0; i < auths.length; i++) {
      const auth = auths[i];
      auth.authHi = BigInt(i);
      const authHash = hashPublicKey(auth.pubKey);
      await authsTree.insert(i, authHash);
    }

    return new State(authsTree, claimsTree, authRevTree, claimRevTree, auths.length, 0, authDepth, claimDepth);
  }

  /**
   * Insert new auth(public key) to claim tree
   * @param {Auth} auth auth to insert
   * @returns {Promise<Auth>} inserted auth
   */
  async insertAuth(auth: Auth): Promise<Auth> {
    auth.authHi = BigInt(this._authRevNonce);
    const authHash = hashPublicKey(auth.pubKey);
    await this._authsTree.insert(auth.authHi, authHash);
    this._authRevNonce++;
    return auth;
  }
  /**
   * Insert new claim to claim tree
   * @param {Entry} claim claim to insert
   * @param {number} maxAttempTimes maximum number of inserting attempts (in case leaves have the same index)
   * @returns {Promise<Entry>} inserted claim
   */
  async insertClaim(claim: Entry, maxAttempTimes: number = 100): Promise<Entry> {
    claim.setRevocationNonce(BigInt(this._claimRevNonce));
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
    this._claimRevNonce++;
    return claim;
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
   * prepare new claim for inserting
   * @param {Entry} claim claim to insert
   * @param {number} maxAttempTimes maximum number of inserting attempts (in case leaves have the same index)
   * @returns {Promise<Entry>} inserted claim
   */
  async prepareClaimForInsert(claim: Entry, maxAttempTimes: number = 100): Promise<Entry> {
    claim.setRevocationNonce(BigInt(this._claimRevNonce));
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
    this._claimRevNonce += 1;
    return claim;
  }

  async batchRevokeClaim(revNonces: BigInt[]) {
    for (let i = 0; i < revNonces.length; i++) {
      await this._claimRevTree.insert(getZidenParams().F.e(revNonces[i]), getZidenParams().F.zero);
    }
  }

  async revokeClaim(revNonce: BigInt) {
    await this._claimRevTree.insert(getZidenParams().F.e(revNonce), getZidenParams().F.zero);
  }

  async revokeAuth(authHi: BigInt) {
    await this._authRevTree.insert(getZidenParams().F.e(authHi), getZidenParams().F.zero);
  }

  /**
   * Generate Auth Exist Proof for an auth in auth tree
   */
  async generateAuthExistsProof(authHi: BigInt): Promise<AuthExistsProof> {
    const F = getZidenParams().F;
    const res = await this._authsTree.find(F.e(authHi));
    if (!res.found) {
      throw new Error('auth is not inserted to the auth tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
    while (siblings.length < this._authDepth * 4) siblings.push(BigInt(0));
    return {
      authMTP: siblings,
      authsRoot: F.toObject(this._authsTree.root),
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
      throw new Error('claim is not inserted to the claim tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(getZidenParams().F.toObject(res.siblings[i]));
    while (siblings.length < this._claimDepth * 4) siblings.push(BigInt(0));
    return {
      claimMTP: siblings,
      treeRoot: getZidenParams().F.toObject(this._claimsTree.root),
    };
  }

  async generateRootsMatchProof(): Promise<RootsMatchProof> {
    const F = getZidenParams().F;
    return {
      authsRoot: F.toObject(this._authsTree.root),
      claimsRoot: F.toObject(this._claimsTree.root),
      authRevRoot: F.toObject(this._authRevTree.root),
      claimRevRoot: F.toObject(this._claimRevTree.root),
      expectedState: bitsToNum(this.getIdenState()),
    };
  }
  /**
   * Generate Claim Not Revoked Proof for a claim in revocation tree
   * @param {BigInt} authHi
   * @returns {Promise<ClaimNotRevokedProof>} claim not revoked proof
   */
  async generateAuthNotRevokedProof(authHi: BigInt): Promise<AuthNotRevokedProof> {
    const F = getZidenParams().F;
    const res = await this._authRevTree.find(F.e(authHi));
    if (res.found) {
      throw new Error('auth is revoked');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
    while (siblings.length < this._authDepth * 4) siblings.push(BigInt(0));
    return {
      authHi,
      authNonRevMTP: siblings,
      authRevRoot: F.toObject(this._authRevTree.root),
      auxHi: F.toObject(res.notFoundKey!),
      auxHv: F.toObject(res.notFoundValue!),
      noAux: res.isOld0 ? BigInt(1) : BigInt(0),
    };
  }

  /**
   * Generate Claim Not Revoked Proof for a claim in revocation tree
   * @param {BigInt} revocationNonce
   * @returns {Promise<ClaimNotRevokedProof>} claim not revoked proof
   */
  async generateClaimNotRevokedProof(revocationNonce: BigInt): Promise<ClaimNotRevokedProof> {
    const F = getZidenParams().F;
    const res = await this._claimRevTree.find(F.e(revocationNonce));
    if (res.found) {
      throw new Error('claim is revoked');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
    while (siblings.length < this._claimDepth * 4) siblings.push(BigInt(0));
    return {
      claimNonRevMTP: siblings,
      treeRoot: F.toObject(this._claimRevTree.root),
      auxHi: F.toObject(res.notFoundKey!),
      auxHv: F.toObject(res.notFoundValue!),
      noAux: res.isOld0 ? BigInt(1) : BigInt(0),
    };
  }

  async CheckAuthProof(authHi: BigInt): Promise<AuthExistsProof> {
    const F = getZidenParams().F;
    const res = await this._authsTree.find(F.e(authHi));
    if (!res.found) {
      throw new Error('auth is not inserted to the auth tree');
    }
    let siblings = [];
    for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
    while (siblings.length < this._authDepth * 4) siblings.push(BigInt(0));
    return {
      authMTP: siblings,
      authsRoot: F.toObject(this._authsTree.root),
    };
  }
}
