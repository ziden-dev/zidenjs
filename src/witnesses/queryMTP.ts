import { Auth, KYCNonRevQueryMTPInput, KYCQueryMTPInput, Query, QueryMTPWitness, SignedChallenge } from '../index.js';
import { Entry } from '../claim/entry.js';
import { State } from '../state/state.js';
import { bitsToNum, createMask, getPartialValue, shiftValue } from '../utils.js';
import {
  idOwnershipBySignatureWitnessWithPrivateKey,
  idOwnershipBySignatureWitnessWithSignature,
} from './authentication.js';
import { createMerkleQueryInput } from './query.js';


/**
 * KYC service Generate credential atomic query MTP witness for Holder
 * 
 * @category queryMTP
 * @async
 * @param {ArrayLike<number>}issuerClaimHi issuer Claim Hi
 * @param {State} issuerState issuer State
 * @returns {KYCQueryMTPInput} KYCQueryMTPInput
 */
export async function kycGenerateQueryMTPInput(
  issuerClaimHi: ArrayLike<number>,
  issuerState: State
): Promise<KYCQueryMTPInput> {
  const claimExistProof = await issuerState.generateClaimExistsProof(issuerClaimHi);
  const rootsMatchProof = await issuerState.generateRootsMatchProof();

  return {
    issuerClaimMtp: claimExistProof.claimMTP,
    issuerClaimAuthsRoot: rootsMatchProof.authsRoot,
    issuerClaimClaimsRoot: rootsMatchProof.claimsRoot,

    issuerClaimClaimRevRoot: rootsMatchProof.claimRevRoot,
    issuerClaimIdenState: rootsMatchProof.expectedState,
    issuerID: bitsToNum(issuerState.userID),
  };
}

/**
 * KYC service Generate credential atomic query Non Rev MTP witness for Holder
 * @category queryMTP
 * @async
 * @param {BigInt}issuerClaimRevNonce issuer Claim revoke nonce
 * @param {State} issuerState issuer State
 * @returns {KYCNonRevQueryMTPInput} KYCQueryMTPInput
 */
export async function kycGenerateNonRevQueryMTPInput(
  issuerClaimRevNonce: BigInt,
  issuerState: State
): Promise<KYCNonRevQueryMTPInput> {
  const claimNotRevokedProof = await issuerState.generateClaimNotRevokedProof(issuerClaimRevNonce);
  const rootsMatchProof = await issuerState.generateRootsMatchProof();

  return {
    issuerClaimNonRevMtp: claimNotRevokedProof.claimNonRevMTP,
    issuerClaimNonRevMtpNoAux: claimNotRevokedProof.noAux,
    issuerClaimNonRevMtpAuxHi: claimNotRevokedProof.auxHi,
    issuerClaimNonRevMtpAuxHv: claimNotRevokedProof.auxHv,
    issuerClaimNonRevAuthsRoot: rootsMatchProof.authsRoot,
    issuerClaimNonRevClaimsRoot: rootsMatchProof.claimsRoot,
    issuerClaimNonRevClaimRevRoot: rootsMatchProof.claimRevRoot,
    issuerClaimNonRevState: rootsMatchProof.expectedState,
  };
}

/**
 * Holder Generate credential atomic query MTP witness from issuer input with private key
 * @category queryMTP
 * @async
 * @param {Entry} issuerClaim issuerClaim
 * @param {Buffer} privateKey privatekey
 * @param {Auth} auth authClaim
 * @param {BigInt} challenge challenge
 * @param {State} state Holder state
 * @param {KYCQueryMTPInput} kycQueryMTPInput  kycQueryMTPInput
 * @param {KYCNonRevQueryMTPInput} kycQueryNonRevMTPInput kycQueryNonRevMTPInput
 * @param {Query} query query
 * @returns {QueryMTPWitness} QueryMTPWitness
 */
export async function holderGenerateQueryMTPWitnessWithPrivateKey(
  issuerClaim: Entry,
  privateKey: Buffer,
  auth: Auth,
  challenge: BigInt,
  state: State,
  kycQueryMTPInput: KYCQueryMTPInput,
  kycQueryNonRevMTPInput: KYCNonRevQueryMTPInput,
  query: Query
): Promise<QueryMTPWitness> {
  const idOwnershipProof = await idOwnershipBySignatureWitnessWithPrivateKey(privateKey, auth, challenge, state);
  const mask = createMask(query.from, query.to);
  const slotValue = bitsToNum(issuerClaim.getSlotData(query.slotIndex));
  const merkleQueryInput = createMerkleQueryInput(
    query.values.map((value) => shiftValue(value, query.from)),
    query.valueTreeDepth,
    getPartialValue(slotValue, query.from, query.to),
    query.operator
  );

  return {
    ...idOwnershipProof,
    ...merkleQueryInput,
    ...kycQueryMTPInput,
    ...kycQueryNonRevMTPInput,
    claimSchema: query.claimSchema,
    slotIndex: query.slotIndex,
    operator: query.operator,
    timestamp: query.timestamp,
    mask,
    issuerClaim: issuerClaim.getDataForCircuit(),
    userID: bitsToNum(state.userID),
  };
}

/**
 * Holder Generate credential atomic query MTP witness from issuer input with private key
 * @category queryMTP
 * @async
 * @param {Entry} issuerClaim issuerClaim
 * @param {SignedChallenge} signature signature
 * @param {Auth} auth authClaim
 * @param {State} state Holder state
 * @param {KYCQueryMTPInput} kycQueryMTPInput  kycQueryMTPInput
 * @param {KYCNonRevQueryMTPInput} kycQueryNonRevMTPInput kycQueryNonRevMTPInput
 * @param {Query} query query
 * @returns {QueryMTPWitness} QueryMTPWitness
 */
export async function holderGenerateQueryMTPWitnessWithSignature(
  issuerClaim: Entry,
  signature: SignedChallenge,
  auth: Auth,
  state: State,
  kycQueryMTPInput: KYCQueryMTPInput,
  kycQueryNonRevMTPInput: KYCNonRevQueryMTPInput,
  query: Query
): Promise<QueryMTPWitness> {
  const idOwnershipProof = await idOwnershipBySignatureWitnessWithSignature(signature, auth, state);
  const mask = createMask(query.from, query.to);
  const slotValue = bitsToNum(issuerClaim.getSlotData(query.slotIndex));
  const merkleQueryInput = createMerkleQueryInput(
    query.values.map((value) => shiftValue(value, query.from)),
    query.valueTreeDepth,
    getPartialValue(slotValue, query.from, query.to),
    query.operator
  );

  return {
    ...idOwnershipProof,
    ...merkleQueryInput,
    ...kycQueryMTPInput,
    ...kycQueryNonRevMTPInput,
    claimSchema: query.claimSchema,
    slotIndex: query.slotIndex,
    operator: query.operator,
    timestamp: query.timestamp,
    mask,
    issuerClaim: issuerClaim.getDataForCircuit(),
    userID: bitsToNum(state.userID),
  };
}
