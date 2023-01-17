import { Auth, IdOwnershipBySignatureWitness, SignedChallenge } from '../index.js';
import { signChallenge } from '../state/auth.js';
import { State } from '../state/state.js';

/**
 * Generate authentication witness from private key
 */
export async function idOwnershipBySignatureWitnessWithPrivateKey(
  privateKey: Buffer,
  auth: Auth,
  challenge: BigInt,
  state: State
): Promise<IdOwnershipBySignatureWitness> {
  const signature = await signChallenge(privateKey, challenge);
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi);
  const rootsMatchProof = await state.generateRootsMatchProof();
  return {
    ...signature,
    userState: rootsMatchProof.expectedState,
    userAuthsRoot: rootsMatchProof.authsRoot,
    userAuthMtp: authExistsProof.authMTP,
    userAuthHi: auth.authHi,
    userAuthPubX: auth.pubKey.X,
    userAuthPubY: auth.pubKey.Y,
    userClaimsRoot: rootsMatchProof.claimsRoot,
    userClaimRevRoot: rootsMatchProof.claimRevRoot,
  };
}

/**
 * Generate authentication witness with signature
 */
export async function idOwnershipBySignatureWitnessWithSignature(
  signature: SignedChallenge,
  auth: Auth,
  state: State
): Promise<IdOwnershipBySignatureWitness> {
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi);
  const rootsMatchProof = await state.generateRootsMatchProof();
  return {
    ...signature,
    userState: rootsMatchProof.expectedState,
    userAuthsRoot: rootsMatchProof.authsRoot,
    userAuthMtp: authExistsProof.authMTP,
    userAuthHi: auth.authHi,
    userAuthPubX: auth.pubKey.X,
    userAuthPubY: auth.pubKey.Y,
    userClaimsRoot: rootsMatchProof.claimsRoot,
    userClaimRevRoot: rootsMatchProof.claimRevRoot,
  };
}
