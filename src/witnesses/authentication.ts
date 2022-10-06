import { Entry } from '../claim/entry.js';
import { EDDSA } from '../global.js';
import { Trees } from '../trees/trees.js';
import { signChallenge, SignedChallenge } from '../claim/auth-claim.js';

export interface AuthenticationWitness extends IdOwnershipBySignatureWitness {
  readonly userID: BigInt;
}
/**
 * Generate authentication witness
 * @param {EDDSA} eddsa
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} trees
 * @returns {Promise<AuthenticationWitness>} authentication circuit input
 */
export async function authenticationWitness(
  eddsa: EDDSA,
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  trees: Trees
): Promise<AuthenticationWitness> {
  const signature = await signChallenge(eddsa, trees.F, privateKey, challenge);
  const authClaimProof = await trees.generateProofForClaim(
    authClaim.hiRaw(trees.hasher),
    authClaim.getRevocationNonce()
  );
  return {
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

    userState: authClaimProof.state,
    userID: authClaimProof.id,
  };
}

export interface IdOwnershipBySignatureWitness extends SignedChallenge{

  readonly userClaimsTreeRoot: BigInt;
  readonly userAuthClaimMtp: Array<BigInt>;
  readonly userAuthClaim: Array<BigInt>;

  readonly userRevTreeRoot: BigInt;
  readonly userAuthClaimNonRevMtp: Array<BigInt>;
  readonly userAuthClaimNonRevMtpNoAux: number | BigInt;
  readonly userAuthClaimNonRevMtpAuxHv: number | BigInt;
  readonly userAuthClaimNonRevMtpAuxHi: number | BigInt;

  readonly userRootsTreeRoot: BigInt;

  readonly userState: BigInt;
}
/**
 * Generate authentication witness
 * @param {EDDSA} eddsa
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} trees
 * @returns {Promise<IdOwnershipBySignatureWitness>} authentication circuit input
 */
export async function idOwnershipBySignatureWitness(
  eddsa: EDDSA,
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  trees: Trees
): Promise<IdOwnershipBySignatureWitness> {
  const signature = await signChallenge(eddsa, trees.F, privateKey, challenge);
  const authClaimProof = await trees.generateProofForClaim(
    authClaim.hiRaw(trees.hasher),
    authClaim.getRevocationNonce()
  );
  return {
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

    userState: authClaimProof.state,
  };
}
