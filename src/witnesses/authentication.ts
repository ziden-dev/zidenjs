import { Entry } from '../claim/entry.js';
import { Trees } from '../trees/trees.js';
import { signChallenge, SignedChallenge } from '../claim/auth-claim.js';

export interface AuthenticationWitness extends IdOwnershipBySignatureWitness {
  readonly userID: BigInt;
}
/**
 * Generate authentication witness
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} trees
 * @returns {Promise<AuthenticationWitness>} authentication circuit input
 */
export async function authenticationWitness(
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  trees: Trees
): Promise<AuthenticationWitness> {
  const signature = await signChallenge(privateKey, challenge);
  const authClaimProof = await trees.generateProofForAuthClaim(
    authClaim.hiRaw()
  );
  return {
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),

    userAuthTreeRoot: authClaimProof.authTreeRoot,

    userState: authClaimProof.state,
    userID: authClaimProof.id,
  };
}

/**
 * Generate authentication witness with signature
 * @param {SignedChallenge} signature
 * @param {Entry} authClaim
 * @param {Trees} trees
 * @returns {Promise<AuthenticationWitness>} authentication circuit input
 */
 export async function authenticationWitnessWithSignature(
  signature: SignedChallenge,
  authClaim: Entry,
  trees: Trees
): Promise<AuthenticationWitness> {
  const authClaimProof = await trees.generateProofForAuthClaim(
    authClaim.hiRaw()
  );
  return {
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),

    userAuthTreeRoot: authClaimProof.authTreeRoot,

    userState: authClaimProof.state,
    userID: authClaimProof.id,
  };
}

export interface IdOwnershipBySignatureWitness extends SignedChallenge{

  readonly userClaimsTreeRoot: BigInt;
  readonly userAuthClaimMtp: Array<BigInt>;
  readonly userAuthClaim: Array<BigInt>;

  readonly userAuthTreeRoot: BigInt;

  readonly userState: BigInt;
}
/**
 * Generate authentication witness
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} trees
 * @returns {Promise<IdOwnershipBySignatureWitness>} idOwnership circuit input
 */
export async function idOwnershipBySignatureWitness(
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  trees: Trees
): Promise<IdOwnershipBySignatureWitness> {
  const signature = await signChallenge(privateKey, challenge);
  const authClaimProof = await trees.generateProofForAuthClaim(
    authClaim.hiRaw()
  );
  return {
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),

    userAuthTreeRoot: authClaimProof.authTreeRoot,

    userState: authClaimProof.state,
  };
}


/**
 * Generate authentication witness with signature
 * @param {SignedChallenge} signature
 * @param {Entry} authClaim
 * @param {Trees} trees
 * @returns {Promise<IdOwnershipBySignatureWitness>} idOwnership circuit input
 */
 export async function idOwnershipBySignatureWitnessWithSignature(
  signature: SignedChallenge,
  authClaim: Entry,
  trees: Trees
): Promise<IdOwnershipBySignatureWitness> {
  const authClaimProof = await trees.generateProofForAuthClaim(
    authClaim.hiRaw()
  );
  return {
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),

    userAuthTreeRoot: authClaimProof.authTreeRoot,

    userState: authClaimProof.state,
  };
}