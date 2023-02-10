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
  if (kycQueryNonRevMTPInput.issuerClaimNonRevMtpAuxHv === issuerClaim.getVersion()) {
    throw new Error('claim is revoke');
  }
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
