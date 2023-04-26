import { getZidenParams } from '../global.js';
import { Gist } from '../gist/gist.js';
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
  state: State,
  gist: Gist
): Promise<IdOwnershipBySignatureWitness> {
  const F = getZidenParams().F;
  let ABC = state.genesisID;
  console.log('X _1 = ', ABC);
  console.log('Y _1 = ', F.toObject(ABC));
  const genesis = await state.generateGenesisProof();
  console.log('X _2 = ', ABC);
  console.log('Y _2 = ', F.toObject(ABC));
  const signature = await signChallenge(privateKey, challenge); //?
  console.log('X _3 = ', ABC);
  console.log('Y _3 = ', F.toObject(ABC));
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi); //?
  ABC = state.genesisID;
  console.log('X _4 = ', ABC);
  console.log('Y _4 = ', F.toObject(ABC));

  const rootsMatchProof = await state.generateRootsMatchProof();
  const gistProof = await gist.generateGistProof(F.toObject(zidenParams.hasher([state.genesisID])));
  return {
    ...gistProof,
    ...genesis,
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
  state: State,
  gist: Gist
): Promise<IdOwnershipBySignatureWitness> {
  const F = zidenParams.F;
  const genesis = await state.generateGenesisProof();
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi);
  const rootsMatchProof = await state.generateRootsMatchProof();
  const gistProof = await gist.generateGistProof(F.toObject(zidenParams.hasher([genesis.genesisID])));
  return {
    ...gistProof,
    ...genesis,
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
