import { signChallenge, SignedChallenge } from '../claim/auth-claim.js';
import { Entry } from '../claim/entry.js';
import { Trees } from '../trees/trees.js';
import { bitsToNum, createMask, getPartialValue } from '../utils.js';
import { compressInputs, createMerkleQueryInput, MerkleQueryInput, OPERATOR } from './query.js';

export interface KYCQueryMTPInput {
  issuerClaimMtp: Array<BigInt>;
  issuerClaimClaimsTreeRoot: BigInt;
  issuerClaimAuthTreeRoot: BigInt;
  issuerClaimIdenState: BigInt;
  issuerID: BigInt;
}
/**
 * KYC service Generate credential atomic query MTP witness for Holder
 * @param {ArrayLike<number>} issuerClaimHi
 * @param {Trees} issuerClaimTrees trees of issuer, include issuerClaim
 * @returns {Promise<KYCQueryMTPInput>} queryMTP input
 */
export async function kycGenerateQueryMTPInput(
  issuerClaimHi: ArrayLike<number>,
  issuerClaimTrees: Trees
): Promise<KYCQueryMTPInput> {
  const issuerClaimProof = await issuerClaimTrees.generateProofForClaim(issuerClaimHi);

  return {
    issuerClaimMtp: issuerClaimProof.claimMTP,
    issuerClaimClaimsTreeRoot: issuerClaimProof.claimsTreeRoot,
    issuerClaimAuthTreeRoot: issuerClaimProof.authTreeRoot,
    issuerClaimIdenState: issuerClaimProof.state,
    issuerID: bitsToNum(issuerClaimTrees.userID),
  };
}

export interface QueryMTPWitness extends KYCQueryMTPInput, SignedChallenge, MerkleQueryInput {
  readonly userID: BigInt;
  readonly userState: BigInt;
  readonly userClaimsTreeRoot: BigInt;
  readonly userAuthClaimMtp: Array<BigInt>;
  readonly userAuthClaim: Array<BigInt>;
  readonly userAuthTreeRoot: BigInt;
  readonly compactInput: BigInt;
  readonly mask: BigInt;
  readonly issuerClaim: Array<BigInt>;
}

/**
 * Holder Generate credential atomic query MTP witness from issuer input
 * @param {Entry} issuerClaim
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} userTrees
 * @param {KYCQueryMTPInput} kycQueryMTPInput
 * @param {number} slotIndex
 * @param {OPERATOR} operator
 * @param {Array<BigInt>} values
 * @param {number} valueTreeDepth
 * @param {number} from
 * @param {number} to
 * @param {number} timestamp
 * @returns {Promise<QueryMTPWitness>} queryMTP witness
 */
export async function holderGenerateQueryMTPWitness(
  issuerClaim: Entry,
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  userTrees: Trees,
  kycQueryMTPInput: KYCQueryMTPInput,
  slotIndex: number,
  operator: OPERATOR,
  values: Array<BigInt>,
  valueTreeDepth: number,
  from: number,
  to: number,
  timestamp: number
): Promise<QueryMTPWitness> {
  const signature = await signChallenge(privateKey, challenge);
  const authClaimProof = await userTrees.generateProofForAuthClaim(authClaim.hiRaw());
  const claimSchema = bitsToNum(issuerClaim.getSchemaHash());
  const compactInput = compressInputs(timestamp, claimSchema, slotIndex, operator);
  const mask = createMask(from, to);
  const slotValue = bitsToNum(issuerClaim.getSlotData(slotIndex));
  const merkleQueryInput = createMerkleQueryInput(
    values,
    valueTreeDepth,
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
    issuerClaim: issuerClaim.getDataForCircuit(),
    userAuthTreeRoot: authClaimProof.authTreeRoot,
    compactInput,
    mask,
    ...merkleQueryInput,
    ...kycQueryMTPInput,
  };
}

/**
 * Holder Generate credential atomic query MTP witness from issuer input with signature
 * @param {Entry} issuerClaim
 * @param {Entry} authClaim
 * @param {SignedChallenge} signature
 * @param {Trees} userAuthTrees
 * @param {KYCQueryMTPInput} kycQueryMTPInput
 * @param {KYCNonRevQueryMTPInput} kycQueryNonRevMTPInput
 * @param {number} slotIndex
 * @param {OPERATOR} operator
 * @param {Array<BigInt>} values
 * @param {number} valueTreeDepth
 * @param {number} from
 * @param {number} to
 * @param {number} timestamp
 * @returns {Promise<QueryMTPWitness>} queryMTP witness
 */
export async function holderGenerateQueryMTPWitnessWithSignature(
  issuerClaim: Entry,
  authClaim: Entry,
  signature: SignedChallenge,
  userAuthTrees: Trees,
  kycQueryMTPInput: KYCQueryMTPInput,
  slotIndex: number,
  operator: OPERATOR,
  values: Array<BigInt>,
  valueTreeDepth: number,
  from: number,
  to: number,
  timestamp: number
): Promise<QueryMTPWitness> {
  const authClaimProof = await userAuthTrees.generateProofForAuthClaim(authClaim.hiRaw());
  const claimSchema = bitsToNum(issuerClaim.getSchemaHash());
  const compactInput = compressInputs(timestamp, claimSchema, slotIndex, operator);
  const mask = createMask(from, to);
  const slotValue = bitsToNum(issuerClaim.getSlotData(slotIndex));
  const merkleQueryInput = createMerkleQueryInput(
    values,
    valueTreeDepth,
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
    issuerClaim: issuerClaim.getDataForCircuit(),
    userAuthTreeRoot: authClaimProof.authTreeRoot,
    compactInput,
    mask,
    ...merkleQueryInput,
    ...kycQueryMTPInput
  };
}
