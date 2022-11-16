import { Trees } from '../trees/trees.js';
import { signChallenge, SignedChallenge } from '../claim/auth-claim.js';
import { Entry } from '../claim/entry.js';
import { numToBits } from '../utils.js';
import { getZidenParams } from '../global.js';

export interface StateTransitionWitness {
  readonly userID: BigInt;
  readonly oldUserState: BigInt;
  readonly newUserState: BigInt;
  readonly isOldStateGenesis: number;
  readonly claimsTreeRoot: BigInt;
  readonly authClaimMtp: Array<BigInt>;
  readonly authClaim: Array<BigInt>;

  readonly revTreeRoot: BigInt;
  readonly authClaimNonRevMtp: Array<BigInt>;
  readonly authClaimNonRevMtpNoAux: number | BigInt;
  readonly authClaimNonRevMtpAuxHv: number | BigInt;
  readonly authClaimNonRevMtpAuxHi: number | BigInt;

  readonly rootsTreeRoot: BigInt;
  readonly signatureR8x: BigInt;
  readonly signatureR8y: BigInt;
  readonly signatureS: BigInt;
}

/**
 * Update trees state through insert claims into claims tree and revoke claims
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {Trees} trees
 * @param {Array<Entry>} insertingClaims claims inserted to claims tree
 * @param {Array<BigInt>} revokingClaimsRevNonce revoked claims
 * @returns {Promise<StateTransitionWitness>} state transition witness
 */
export async function stateTransitionWitness(
  privateKey: Buffer,
  authClaim: Entry,
  trees: Trees,
  insertingClaims: Array<Entry>,
  revokingClaimsRevNonce: Array<BigInt>,
): Promise<StateTransitionWitness> {
  const userID = trees.userID;
  const oldUserState = trees.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(numToBits(oldUserState, 32).subarray(-29)) ? 1 : 0;
  const authClaimProof = await trees.generateProofForClaim(
    authClaim.hiRaw(),
    authClaim.getRevocationNonce()
  );
  for (let i = 0; i < insertingClaims.length; i++) {
    await trees.insertClaim(insertingClaims[i]);
  }
  for (let i = 0; i < revokingClaimsRevNonce.length; i++) {
    await trees.revokeClaim(revokingClaimsRevNonce[i]);
  }

  const newUserState = trees.getIdenState();
  const challenge = getZidenParams().hasher([oldUserState, newUserState]);
  const signature = await signChallenge(privateKey, challenge);
  return {
    userID: authClaimProof.id,
    oldUserState,
    newUserState,
    isOldStateGenesis,
    claimsTreeRoot: authClaimProof.claimsTreeRoot,
    authClaimMtp: authClaimProof.claimMTP,
    authClaim: authClaim.getDataForCircuit(),

    revTreeRoot: authClaimProof.revTreeRoot,
    authClaimNonRevMtp: authClaimProof.claimNonRevMTP,
    authClaimNonRevMtpNoAux: authClaimProof.claimNonRevNoAux,
    authClaimNonRevMtpAuxHv: authClaimProof.claimNonRevAuxHv,
    authClaimNonRevMtpAuxHi: authClaimProof.claimNonRevAuxHi,

    rootsTreeRoot: authClaimProof.rootsTreeRoot,

    signatureR8x: signature.challengeSignatureR8x,
    signatureR8y: signature.challengeSignatureR8y,
    signatureS: signature.challengeSignatureS,
  };
}

/**
 * Update trees state through insert claims by hi, hv into claims tree and revoke claims
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {Trees} trees
 * @param {Array<[ArrayLike<number>, ArrayLike<number>]>} insertingClaimHiHvs claims inserted to claims tree
 * @param {Array<BigInt>} revokingClaimsRevNonce revoked claims
 * @returns {Promise<StateTransitionWitness>} state transition witness
 */
export async function stateTransitionWitnessWithHiHv(
  privateKey: Buffer,
  authClaim: Entry,
  trees: Trees,
  insertingClaimHiHvs: Array<[ArrayLike<number>, ArrayLike<number>]>,
  revokingClaimsRevNonce: Array<BigInt>
): Promise<StateTransitionWitness> {
  const userID = trees.userID;
  const oldUserState = trees.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(numToBits(oldUserState, 32).subarray(-29)) ? 1 : 0;
  const authClaimProof = await trees.generateProofForClaim(
    authClaim.hiRaw(),
    authClaim.getRevocationNonce()
  );
  await trees.batchInsertClaimByHiHv(insertingClaimHiHvs);
  await trees.batchRevokeClaim(revokingClaimsRevNonce);

  const newUserState = trees.getIdenState();
  const challenge = getZidenParams().hasher([oldUserState, newUserState]);
  const signature = await signChallenge(privateKey, challenge);
  return {
    userID: authClaimProof.id,
    oldUserState,
    newUserState,
    isOldStateGenesis,
    claimsTreeRoot: authClaimProof.claimsTreeRoot,
    authClaimMtp: authClaimProof.claimMTP,
    authClaim: authClaim.getDataForCircuit(),

    revTreeRoot: authClaimProof.revTreeRoot,
    authClaimNonRevMtp: authClaimProof.claimNonRevMTP,
    authClaimNonRevMtpNoAux: authClaimProof.claimNonRevNoAux,
    authClaimNonRevMtpAuxHv: authClaimProof.claimNonRevAuxHv,
    authClaimNonRevMtpAuxHi: authClaimProof.claimNonRevAuxHi,

    rootsTreeRoot: authClaimProof.rootsTreeRoot,

    signatureR8x: signature.challengeSignatureR8x,
    signatureR8y: signature.challengeSignatureR8y,
    signatureS: signature.challengeSignatureS,
  };
}

/**
 * Update trees state through insert claims into claims tree and revoke claims
 * @param {SignedChallenge} signature
 * @param {Entry} authClaim
 * @param {Trees} trees
 * @param {Array<Entry>} insertingClaims claims inserted to claims tree
 * @param {Array<BigInt>} revokingClaimsRevNonce revoked claims
 * @returns {Promise<StateTransitionWitness>} state transition witness
 */
 export async function stateTransitionWitnessWithSignature(
  signature: SignedChallenge,
  authClaim: Entry,
  trees: Trees,
  insertingClaims: Array<Entry>,
  revokingClaimsRevNonce: Array<BigInt>,
): Promise<StateTransitionWitness> {
  const userID = trees.userID;
  const oldUserState = trees.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(numToBits(oldUserState, 32).subarray(-29)) ? 1 : 0;
  const authClaimProof = await trees.generateProofForClaim(
    authClaim.hiRaw(),
    authClaim.getRevocationNonce()
  );
  for (let i = 0; i < insertingClaims.length; i++) {
    await trees.insertClaim(insertingClaims[i]);
  }
  for (let i = 0; i < revokingClaimsRevNonce.length; i++) {
    await trees.revokeClaim(revokingClaimsRevNonce[i]);
  }

  const newUserState = trees.getIdenState();
  return {
    userID: authClaimProof.id,
    oldUserState,
    newUserState,
    isOldStateGenesis,
    claimsTreeRoot: authClaimProof.claimsTreeRoot,
    authClaimMtp: authClaimProof.claimMTP,
    authClaim: authClaim.getDataForCircuit(),

    revTreeRoot: authClaimProof.revTreeRoot,
    authClaimNonRevMtp: authClaimProof.claimNonRevMTP,
    authClaimNonRevMtpNoAux: authClaimProof.claimNonRevNoAux,
    authClaimNonRevMtpAuxHv: authClaimProof.claimNonRevAuxHv,
    authClaimNonRevMtpAuxHi: authClaimProof.claimNonRevAuxHi,

    rootsTreeRoot: authClaimProof.rootsTreeRoot,

    signatureR8x: signature.challengeSignatureR8x,
    signatureR8y: signature.challengeSignatureR8y,
    signatureS: signature.challengeSignatureS,
  };
}

/**
 * Update trees state through insert claims by hi, hv into claims tree and revoke claims with signature
 * @param {SignedChallenge} signature
 * @param {Entry} authClaim
 * @param {Trees} trees
 * @param {Array<[ArrayLike<number>, ArrayLike<number>]>} insertingClaimHiHvs claims inserted to claims tree
 * @param {Array<BigInt>} revokingClaimsRevNonce revoked claims
 * @returns {Promise<StateTransitionWitness>} state transition witness
 */
 export async function stateTransitionWitnessWithHiHvWithSignature(
  signature: SignedChallenge,
  authClaim: Entry,
  trees: Trees,
  insertingClaimHiHvs: Array<[ArrayLike<number>, ArrayLike<number>]>,
  revokingClaimsRevNonce: Array<BigInt>,
): Promise<StateTransitionWitness> {
  const userID = trees.userID;
  const oldUserState = trees.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(numToBits(oldUserState, 32).subarray(-29)) ? 1 : 0;
  const authClaimProof = await trees.generateProofForClaim(
    authClaim.hiRaw(),
    authClaim.getRevocationNonce()
  );
  await trees.batchInsertClaimByHiHv(insertingClaimHiHvs);
  await trees.batchRevokeClaim(revokingClaimsRevNonce);

  const newUserState = trees.getIdenState();

  return {
    userID: authClaimProof.id,
    oldUserState,
    newUserState,
    isOldStateGenesis,
    claimsTreeRoot: authClaimProof.claimsTreeRoot,
    authClaimMtp: authClaimProof.claimMTP,
    authClaim: authClaim.getDataForCircuit(),

    revTreeRoot: authClaimProof.revTreeRoot,
    authClaimNonRevMtp: authClaimProof.claimNonRevMTP,
    authClaimNonRevMtpNoAux: authClaimProof.claimNonRevNoAux,
    authClaimNonRevMtpAuxHv: authClaimProof.claimNonRevAuxHv,
    authClaimNonRevMtpAuxHi: authClaimProof.claimNonRevAuxHi,

    rootsTreeRoot: authClaimProof.rootsTreeRoot,

    signatureR8x: signature.challengeSignatureR8x,
    signatureR8y: signature.challengeSignatureR8y,
    signatureS: signature.challengeSignatureS,
  };
}