import { EDDSA, Hasher, SnarkField } from '../global.js';
import { Trees } from '../trees/trees.js';
import { signChallenge, SignedChallenge } from '../claim/auth-claim.js';
import { Entry } from '../claim/entry.js';
import { bitsToNum, createMask, getPartialValue, shiftValue } from '../utils.js';
import { compressInputs, createMerkleQueryInput, MerkleQueryInput, OPERATOR } from './query.js';
import { HashFunction } from './fixed-merkle-tree/index.js';

export interface KYCQuerySigInput {
  readonly issuerClaimSignatureR8x: BigInt;
  readonly issuerClaimSignatureR8y: BigInt;
  readonly issuerClaimSignatureS: BigInt;
  readonly issuerID: BigInt;
  readonly issuerAuthClaim: Array<BigInt>;
  readonly issuerAuthClaimMtp: Array<BigInt>;
  readonly issuerAuthClaimNonRevMtp: Array<BigInt>;
  readonly issuerAuthClaimNonRevMtpNoAux: BigInt | number;
  readonly issuerAuthClaimNonRevMtpAuxHi: BigInt | number;
  readonly issuerAuthClaimNonRevMtpAuxHv: BigInt | number;
  readonly issuerAuthClaimsTreeRoot: BigInt;
  readonly issuerAuthRevTreeRoot: BigInt;
  readonly issuerAuthRootsTreeRoot: BigInt;
}
/**
 * KYC service Generate query sig witness for Holder
 * @param {EDDSA} eddsa
 * @param {Hasher} hasher
 * @param {Buffer} privateKey
 * @param {Entry} issuerAuthClaim
 * @param {Entry} issuerClaim
 * @param {Trees} issuerAuthClaimTrees trees of issuer, include issuerClaim
 * @returns {Promise<KYCQuerySigInput>} queryMTP input
 */
export async function kycGenerateQuerySigInput(
  eddsa: EDDSA,
  hasher: Hasher,
  privateKey: Buffer,
  issuerAuthClaim: Entry,
  issuerClaim: Entry,
  issuerAuthClaimTrees: Trees
): Promise<KYCQuerySigInput> {
  const challenge = issuerClaim.getClaimHash(hasher, issuerAuthClaimTrees.F);
  const claimSignature = await signChallenge(eddsa, issuerAuthClaimTrees.F, privateKey, challenge);

  const issuerAuthClaimProof = await issuerAuthClaimTrees.generateProofForClaim(
    issuerAuthClaim.hiRaw(issuerAuthClaimTrees.hasher),
    issuerAuthClaim.getRevocationNonce()
  );

  return {
    issuerClaimSignatureR8x: claimSignature.challengeSignatureR8x,
    issuerClaimSignatureR8y: claimSignature.challengeSignatureR8y,
    issuerClaimSignatureS: claimSignature.challengeSignatureS,
    issuerID: issuerAuthClaimProof.id,
    issuerAuthClaim: issuerAuthClaim.getDataForCircuit(),
    issuerAuthClaimMtp: issuerAuthClaimProof.claimMTP,
    issuerAuthClaimNonRevMtp: issuerAuthClaimProof.claimNonRevMTP,
    issuerAuthClaimNonRevMtpNoAux: issuerAuthClaimProof.claimNonRevNoAux,
    issuerAuthClaimNonRevMtpAuxHi: issuerAuthClaimProof.claimNonRevAuxHi,
    issuerAuthClaimNonRevMtpAuxHv: issuerAuthClaimProof.claimNonRevAuxHv,
    issuerAuthClaimsTreeRoot: issuerAuthClaimProof.claimsTreeRoot,
    issuerAuthRevTreeRoot: issuerAuthClaimProof.revTreeRoot,
    issuerAuthRootsTreeRoot: issuerAuthClaimProof.rootsTreeRoot,
  };
}

export interface KYCQuerySigNonRevInput {
  readonly issuerClaimNonRevMtp: Array<BigInt>;
  readonly issuerClaimNonRevMtpNoAux: number | BigInt;
  readonly issuerClaimNonRevMtpAuxHi: number | BigInt;
  readonly issuerClaimNonRevMtpAuxHv: number | BigInt;
  readonly issuerClaimNonRevClaimsTreeRoot: BigInt;
  readonly issuerClaimNonRevRevTreeRoot: BigInt;
  readonly issuerClaimNonRevRootsTreeRoot: BigInt;
  readonly issuerClaimNonRevState: BigInt;
}
/**
 * KYC service Generate query sig nonrev witness for Holder
 * @param {BigInt} revocationNonce
 * @param {Trees} issuerClaimNonRevTrees trees of issuer, not revoke issuerClaim
 * @returns {Promise<KYCQuerySigNonRevInput>} querySig NonRev input
 */
export async function kycGenerateQuerySigNonRevInput(
  revocationNonce: BigInt,
  issuerClaimNonRevTrees: Trees
): Promise<KYCQuerySigNonRevInput> {
  const issuerClaimNonRevProof = await issuerClaimNonRevTrees.generateClaimFullNotRevokedProof(revocationNonce);
  return {
    issuerClaimNonRevMtp: issuerClaimNonRevProof.claimNonRevMTP,
    issuerClaimNonRevMtpNoAux: issuerClaimNonRevProof.claimNonRevNoAux,
    issuerClaimNonRevMtpAuxHi: issuerClaimNonRevProof.claimNonRevAuxHi,
    issuerClaimNonRevMtpAuxHv: issuerClaimNonRevProof.claimNonRevAuxHv,
    issuerClaimNonRevClaimsTreeRoot: issuerClaimNonRevProof.claimsTreeRoot,
    issuerClaimNonRevRevTreeRoot: issuerClaimNonRevProof.revTreeRoot,
    issuerClaimNonRevRootsTreeRoot: issuerClaimNonRevProof.rootsTreeRoot,
    issuerClaimNonRevState: issuerClaimNonRevProof.state,
  };
}

export interface QuerySigWitness extends KYCQuerySigInput, KYCQuerySigNonRevInput, SignedChallenge, MerkleQueryInput {
  readonly userID: BigInt;
  readonly userState: BigInt;
  readonly userClaimsTreeRoot: BigInt;
  readonly userAuthClaimMtp: Array<BigInt>;
  readonly userAuthClaim: Array<BigInt>;

  readonly userRevTreeRoot: BigInt;
  readonly userAuthClaimNonRevMtp: Array<BigInt>;
  readonly userAuthClaimNonRevMtpNoAux: BigInt | number;
  readonly userAuthClaimNonRevMtpAuxHv: BigInt | number;
  readonly userAuthClaimNonRevMtpAuxHi: BigInt | number;

  readonly userRootsTreeRoot: BigInt;

  readonly compactInput: BigInt;
  readonly mask: BigInt;

  issuerClaim: Array<BigInt>;
}
/**
 * Holder Generate credential atomic query sig witness from issuer input
 * @param {Entry} issuerClaim
 * @param {EDDSA} eddsa
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} userAuthTrees
 * @param {KYCQuerySigInput} kycQuerySigInput
 * @param {KYCQuerySigNonRevInput} kycQuerySigNonRevInput
 * @param {number} slotIndex
 * @param {OPERATOR} operator
 * @param {Array<BigInt>} values
 * @param {number} valueTreeDepth
 * @param {number} from
 * @param {number} to
 * @param {HashFunction} hashFunction
 * @param {SnarkField} F
 * @returns {Promise<QuerySigWitness>} querySig witness
 */
export async function holderGenerateQuerySigWitness(
  issuerClaim: Entry,
  eddsa: EDDSA,
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  userAuthTrees: Trees,
  kycQuerySigInput: KYCQuerySigInput,
  kycQuerySigNonRevInput: KYCQuerySigNonRevInput,
  slotIndex: number,
  operator: OPERATOR,
  values: Array<BigInt>,
  valueTreeDepth: number,
  from: number,
  to: number,
  hashFunction: HashFunction,
  F: SnarkField
): Promise<QuerySigWitness> {
  const signature = await signChallenge(eddsa, userAuthTrees.F, privateKey, challenge);
  const authClaimProof = await userAuthTrees.generateProofForClaim(
    authClaim.hiRaw(userAuthTrees.hasher),
    authClaim.getRevocationNonce()
  );
  const timestamp = Date.now();
  const claimSchema = bitsToNum(issuerClaim.getSchemaHash());
  const compactInput = compressInputs(timestamp, claimSchema, slotIndex, operator);
  const mask = createMask(from, to);
  const slotValue = bitsToNum(issuerClaim.getSlotData(slotIndex));
  const merkleQueryInput = createMerkleQueryInput(
    values.map((value) => shiftValue(value, from)),
    valueTreeDepth,
    hashFunction,
    F,
    getPartialValue(slotValue, from, to),
    operator
  );
  return {
    userID: authClaimProof.id,
    userState: authClaimProof.state,
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),
    userRevTreeRoot: authClaimProof.revTreeRoot,
    userAuthClaimNonRevMtp: authClaimProof.claimNonRevMTP,
    userAuthClaimNonRevMtpNoAux: authClaimProof.claimNonRevNoAux,
    userAuthClaimNonRevMtpAuxHv: authClaimProof.claimNonRevAuxHv,
    userAuthClaimNonRevMtpAuxHi: authClaimProof.claimNonRevAuxHi,
    userRootsTreeRoot: authClaimProof.rootsTreeRoot,
    compactInput,
    mask,
    ...merkleQueryInput,
    ...kycQuerySigInput,
    ...kycQuerySigNonRevInput,
    issuerClaim: issuerClaim.getDataForCircuit(),
  };
}
