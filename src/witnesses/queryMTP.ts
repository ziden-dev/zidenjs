import { EDDSA } from 'src/global.js';
import { signChallenge, SignedChallenge } from '../claim/auth-claim.js';
import { Entry } from '../claim/entry.js';
import { Trees } from '../trees/trees.js';
import { bitsToNum } from '../utils.js';

export interface KYCQueryMTPInput {
  issuerClaimMtp: Array<BigInt>;
  issuerClaimClaimsTreeRoot: BigInt;
  issuerClaimRevTreeRoot: BigInt;
  issuerClaimRootsTreeRoot: BigInt;
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
  const issuerClaimProof = await issuerClaimTrees.generateClaimFullExistsProof(issuerClaimHi);

  return {
    issuerClaimMtp: issuerClaimProof.claimMTP,
    issuerClaimClaimsTreeRoot: issuerClaimProof.claimsTreeRoot,
    issuerClaimRevTreeRoot: issuerClaimProof.revTreeRoot,
    issuerClaimRootsTreeRoot: issuerClaimProof.rootsTreeRoot,
    issuerClaimIdenState: issuerClaimProof.state,
    issuerID: bitsToNum(issuerClaimTrees.userID),
  };
}

export interface KYCNonRevQueryMTPInput {
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
 * KYC service Generate credential atomic query Non Rev MTP witness for Holder
 * @param {BigInt} issuerClaimRevNonce
 * @param {Trees} issuerClaimNonRevTrees trees of issuer, not revoke issuerClaim
 * @returns {Promise<KYCNonRevQueryMTPInput>} nonrev queryMTP input
 */
export async function kycGenerateNonRevQueryMTPInput(
  issuerClaimRevNonce: BigInt,
  issuerClaimNonRevTrees: Trees
): Promise<KYCNonRevQueryMTPInput> {
  const issuerClaimNonRevProof = await issuerClaimNonRevTrees.generateClaimFullNotRevokedProof(issuerClaimRevNonce);
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

export interface QueryMTPWitness extends KYCQueryMTPInput, KYCNonRevQueryMTPInput, SignedChallenge {
  readonly userID: BigInt;
  readonly userState: BigInt;
  readonly userClaimsTreeRoot: BigInt;
  readonly userAuthClaimMtp: Array<BigInt>;
  readonly userAuthClaim: Array<BigInt>;
  readonly userRevTreeRoot: BigInt;
  readonly userAuthClaimNonRevMtp: Array<BigInt>;
  readonly userAuthClaimNonRevMtpNoAux: number | BigInt;
  readonly userAuthClaimNonRevMtpAuxHv: number | BigInt;
  readonly userAuthClaimNonRevMtpAuxHi: number | BigInt;
  readonly userRootsTreeRoot: BigInt;
  readonly timestamp: number;
  readonly slotIndex: number;
  readonly operator: number;
  readonly value: Array<BigInt>;
  readonly claimSchema: BigInt;
  readonly issuerClaim: Array<BigInt>;
}
/**
 * Holder Generate credential atomic query MTP witness from issuer input
 * @param {Entry} issuerClaim
 * @param {EDDSA} eddsa
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} userAuthTrees
 * @param {KYCQueryMTPInput} kycQueryMTPInput
 * @param {KYCNonRevQueryMTPInput} kycQueryNonRevMTPInput
 * @param {number} slotIndex
 * @param {number} operator
 * @param {Array<BigInt>} value
 * @returns {Promise<QueryMTPWitness>} queryMTP witness
 */
export async function holderGenerateQueryMTPWitness(
  issuerClaim: Entry,
  eddsa: EDDSA,
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  userAuthTrees: Trees,
  kycQueryMTPInput: KYCQueryMTPInput,
  kycQueryNonRevMTPInput: KYCNonRevQueryMTPInput,
  slotIndex: number,
  operator: number,
  value: Array<BigInt>
): Promise<QueryMTPWitness> {
  const signature = await signChallenge(eddsa, userAuthTrees.F, privateKey, challenge);
  const authClaimProof = await userAuthTrees.generateProofForClaim(
    authClaim.hiRaw(userAuthTrees.hasher),
    authClaim.getRevocationNonce()
  );
  const claimSchema = bitsToNum(issuerClaim.getSchemaHash());
  const timestamp = Date.now();
  return {
    userID: authClaimProof.id,
    userState: authClaimProof.state,
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),
    issuerClaim: issuerClaim.getDataForCircuit(),
    userRevTreeRoot: authClaimProof.revTreeRoot,
    userAuthClaimNonRevMtp: authClaimProof.claimNonRevMTP,
    userAuthClaimNonRevMtpNoAux: authClaimProof.claimNonRevNoAux,
    userAuthClaimNonRevMtpAuxHv: authClaimProof.claimNonRevAuxHv,
    userAuthClaimNonRevMtpAuxHi: authClaimProof.claimNonRevAuxHi,
    userRootsTreeRoot: authClaimProof.rootsTreeRoot,
    timestamp,
    slotIndex,
    operator,
    value,
    claimSchema,
    ...kycQueryMTPInput,
    ...kycQueryNonRevMTPInput,
  };
}
