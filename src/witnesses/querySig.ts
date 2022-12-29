// khanh
import { State } from '../state/state.js';
import { Entry } from '../claim/entry.js';
import {
  Auth,
  Query,
  KYCNonRevQuerySigInput,
  KYCQuerySigInput,
  QuerySigWitness,
  SignedChallenge,
  KYCNonRevQueryMTPInput,
} from '../index.js';
import {
  idOwnershipBySignatureWitnessWithPrivateKey,
  idOwnershipBySignatureWitnessWithSignature,
} from './authentication.js';
import { bitsToNum, createMask, getPartialValue, shiftValue } from '../utils.js';
import { createMerkleQueryInput } from './query.js';
import { signChallenge } from '../state/auth.js';
export async function kycGenerateQuerySigInput(
  privateKey: Buffer,
  issuerAuth: Auth,
  issuerClaim: Entry,
  issuerAuthClaimState: State
): Promise<KYCQuerySigInput> {
  const challenge = issuerClaim.getClaimHash();
  const signature = await signChallenge(privateKey, challenge);

  const claimExistProof = await issuerAuthClaimState.generateAuthExistsProof(issuerAuth.authHi);
  const rootsMatchProof = await issuerAuthClaimState.generateRootsMatchProof();
  const authNotRevProof = await issuerAuthClaimState.generateAuthNotRevokedProof(issuerAuth.authHi);
  return {
    /* issuerClaim signals */
    issuerClaimSignatureR8x: signature.challengeSignatureR8x,
    issuerClaimSignatureR8y: signature.challengeSignatureR8y,
    issuerClaimSignatureS: signature.challengeSignatureS,
    /* issuer state */
    issuerID: bitsToNum(issuerAuthClaimState.userID),
    issuerAuthState: rootsMatchProof.expectedState,
    issuerAuthsRoot: claimExistProof.authsRoot,
    issuerAuthMtp: claimExistProof.authMTP,
    issuerAuthHi: issuerAuth.authHi,
    issuerAuthPubX: issuerAuth.pubKey.X,
    issuerAuthPubY: issuerAuth.pubKey.Y,
    issuerAuthRevRoot: authNotRevProof.authRevRoot,
    issuerAuthNonRevMtp: authNotRevProof.authNonRevMTP,
    issuerAuthNonRevMtpNoAux: authNotRevProof.noAux,
    issuerAuthNonRevMtpAuxHi: authNotRevProof.auxHi,
    issuerAuthNonRevMtpAuxHv: authNotRevProof.auxHv,

    issuerClaimsRoot: rootsMatchProof.claimsRoot,
    issuerClaimRevRoot: rootsMatchProof.claimRevRoot,
  };
}

export async function kycGenerateNonRevQuerySigInput(
  issuerClaimRevNonce: BigInt,
  issuerState: State
): Promise<KYCNonRevQuerySigInput> {
  const claimNotRevokedProof = await issuerState.generateClaimNotRevokedProof(issuerClaimRevNonce);
  const rootsMatchProof = await issuerState.generateRootsMatchProof();

  return {
    issuerClaimNonRevMtp: claimNotRevokedProof.claimNonRevMTP,
    issuerClaimNonRevMtpNoAux: claimNotRevokedProof.noAux,
    issuerClaimNonRevMtpAuxHi: claimNotRevokedProof.auxHi,
    issuerClaimNonRevMtpAuxHv: claimNotRevokedProof.auxHv,
    issuerClaimNonRevAuthsRoot: rootsMatchProof.authsRoot,
    issuerClaimNonRevClaimsRoot: rootsMatchProof.claimsRoot,
    issuerClaimNonRevAuthRevRoot: rootsMatchProof.authRevRoot,
    issuerClaimNonRevClaimRevRoot: rootsMatchProof.claimRevRoot,
    issuerClaimNonRevState: rootsMatchProof.expectedState,
  };
}

export async function holderGenerateQuerySigWitnessWithPrivateKey(
  issuerClaim: Entry,
  privateKey: Buffer,
  auth: Auth,
  challenge: BigInt,
  state: State,
  kycQuerySigInput: KYCQuerySigInput,
  kycQueryNonRevSigInput: KYCNonRevQuerySigInput,
  query: Query
): Promise<QuerySigWitness> {
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
    ...kycQuerySigInput,
    ...kycQueryNonRevSigInput,
    claimSchema: query.claimSchema,
    slotIndex: query.slotIndex,
    operator: query.operator,
    timestamp: query.timestamp,
    mask,
    issuerClaim: issuerClaim.getDataForCircuit(),
    userID: bitsToNum(state.userID),
  };
}

export async function holderGenerateQuerySigWitnessWithSignature(
  issuerClaim: Entry,
  signature: SignedChallenge,
  auth: Auth,
  state: State,
  kycQuerySigInput: KYCQuerySigInput,
  kycQueryNonRevSigInput: KYCNonRevQueryMTPInput,
  query: Query
): Promise<QuerySigWitness> {
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
    ...kycQuerySigInput,
    ...kycQueryNonRevSigInput,
    claimSchema: query.claimSchema,
    slotIndex: query.slotIndex,
    operator: query.operator,
    timestamp: query.timestamp,
    mask,
    issuerClaim: issuerClaim.getDataForCircuit(),
    userID: bitsToNum(state.userID),
  };
}
