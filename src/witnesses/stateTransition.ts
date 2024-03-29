import { Entry } from '../claim/entry.js';
import { getZidenParams } from '../global.js';
import { Auth, SignedChallenge, StateTransitionWitness } from 'src/index.js';
import { State } from '../state/state.js';
import { signChallenge } from '../state/auth.js';
import { bitsToNum } from '../utils.js';


/**
 * Update user state with private key
 * @category stateTransition
 * @async
 * @param {Buffer} privateKey privateKey
 * @param {Auth} auth authClaim
 * @param {State} state userState
 * @param {Array<Auth>} insertingAuths AuthClaim array will be added
 * @param {Array<Entry>} insertingClaims Claims array will be added
 * @param {Array<BigInt>} revokingAuthHis AuthClaim array will be revoke (using Hi)
 * @param {Array<BigInt>} revokingClaimRevNonces Claim array will be revoke (using revoke nonces)
 * @returns {Promise<StateTransitionWitness>} State Transition Witness proof
 */
export async function stateTransitionWitnessWithPrivateKey(
  privateKey: Buffer,
  auth: Auth,
  state: State,
  insertingAuths: Array<Auth>,
  insertingClaims: Array<Entry>,
  revokingAuthHis: Array<BigInt>,
  revokingClaimRevNonces: Array<BigInt>
): Promise<StateTransitionWitness> {
  const userID = state.userID;
  const oldUserState = state.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(oldUserState.subarray(-29)) ? 1 : 0;
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi);
  const rootsMatchProof = await state.generateRootsMatchProof();

  for (let i = 0; i < insertingAuths.length; i++) {
    await state.insertAuth(insertingAuths[i]);
  }
  for (let i = 0; i < insertingClaims.length; i++) {
    await state.insertClaim(insertingClaims[i]);
  }
  for (let i = 0; i < revokingAuthHis.length; i++) {
    await state.revokeAuth(revokingAuthHis[i]);
  }
  for (let i = 0; i < revokingClaimRevNonces.length; i++) {
    await state.revokeClaim(revokingClaimRevNonces[i]);
  }
  const newUserState = state.getIdenState();
  const challenge = getZidenParams().hasher([bitsToNum(oldUserState), bitsToNum(newUserState)]);
  const signature = await signChallenge(privateKey, challenge);

  return {
    userID: bitsToNum(userID),
    oldUserState: bitsToNum(oldUserState),
    newUserState: bitsToNum(newUserState),
    isOldStateGenesis,
    userAuthsRoot: rootsMatchProof.authsRoot,
    userAuthMtp: authExistsProof.authMTP,
    userAuthHi: auth.authHi,
    userAuthPubX: auth.pubKey.X,
    userAuthPubY: auth.pubKey.Y,
    userClaimsRoot: rootsMatchProof.claimsRoot,
    userClaimRevRoot: rootsMatchProof.claimRevRoot,
    challengeSignatureR8x: signature.challengeSignatureR8x,
    challengeSignatureR8y: signature.challengeSignatureR8y,
    challengeSignatureS: signature.challengeSignatureS,
  };
}

/**
 * Update user state with Signature
 * @category stateTransition
 * @function
 * @async
 * @param {SignedChallenge} signature signature
 * @param {Auth} auth authClaim
 * @param {State} state userState
 * @param {Array<Auth>} insertingAuths AuthClaim array will be added
 * @param {Array<Entry>} insertingClaims Claims array will be added
 * @param {Array<BigInt>} revokingAuthHis AuthClaim array will be revoke (using Hi)
 * @param {Array<BigInt>} revokingClaimRevNonces Claim array will be revoke (using revoke nonces)
 * @returns {Promise<StateTransitionWitness>} State Transition Witness proof
 */
export async function stateTransitionWitnessWithSignature(
  signature: SignedChallenge,
  auth: Auth,
  state: State,
  insertingAuths: Array<Auth>,
  insertingClaims: Array<Entry>,
  revokingAuthHis: Array<BigInt>,
  revokingClaimRevNonces: Array<BigInt>
): Promise<StateTransitionWitness> {
  const userID = state.userID;
  const oldUserState = state.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(oldUserState.subarray(-29)) ? 1 : 0;
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi);
  const rootsMatchProof = await state.generateRootsMatchProof();
  for (let i = 0; i < insertingAuths.length; i++) {
    await state.insertAuth(insertingAuths[i]);
  }
  for (let i = 0; i < insertingClaims.length; i++) {
    await state.insertClaim(insertingClaims[i]);
  }
  for (let i = 0; i < revokingAuthHis.length; i++) {
    await state.revokeAuth(revokingAuthHis[i]);
  }
  for (let i = 0; i < revokingClaimRevNonces.length; i++) {
    await state.revokeClaim(revokingClaimRevNonces[i]);
  }
  const newUserState = state.getIdenState();

  return {
    userID: bitsToNum(userID),
    oldUserState: bitsToNum(oldUserState),
    newUserState: bitsToNum(newUserState),
    isOldStateGenesis,
    userAuthsRoot: rootsMatchProof.authsRoot,
    userAuthMtp: authExistsProof.authMTP,
    userAuthHi: auth.authHi,
    userAuthPubX: auth.pubKey.X,
    userAuthPubY: auth.pubKey.Y,
    userClaimsRoot: rootsMatchProof.claimsRoot,
    userClaimRevRoot: rootsMatchProof.claimRevRoot,
    challengeSignatureR8x: signature.challengeSignatureR8x,
    challengeSignatureR8y: signature.challengeSignatureR8y,
    challengeSignatureS: signature.challengeSignatureS,
  };
}

/**
 * update user state with privatekey and HiHv-Claim
 * @category stateTransition
 * @async
 * @param {Buffer} privateKey privateKey
 * @param {Auth} auth authClaim
 * @param {State} state userState
 * @param {Array<Auth>} insertingAuths AuthClaim array will be added
 * @param {Array.<{ArrayLike<number>, ArrayLike<number>}>} insertingClaimHiHvs Claims array will be added
 * @param {Array<BigInt>} revokingAuthHis AuthClaim array will be revoke (using Hi)
 * @param {Array<BigInt>} revokingClaimRevNonces Claim array will be revoke (using revoke nonces)
 * @returns {Promise<StateTransitionWitness>} State Transition Witness proof
 */
export async function stateTransitionWitnessWithPrivateKeyAndHiHvs(
  privateKey: Buffer,
  auth: Auth,
  state: State,
  insertingAuths: Array<Auth>,
  insertingClaimHiHvs: Array<[ArrayLike<number>, ArrayLike<number>]>,
  revokingAuthHis: Array<BigInt>,
  revokingClaimRevNonces: Array<BigInt>
): Promise<StateTransitionWitness> {
  const userID = state.userID;
  const oldUserState = state.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(oldUserState.subarray(-29)) ? 1 : 0;
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi);
  const rootsMatchProof = await state.generateRootsMatchProof();
  for (let i = 0; i < insertingAuths.length; i++) {
    await state.insertAuth(insertingAuths[i]);
  }
  await state.batchInsertClaimByHiHv(insertingClaimHiHvs);
  for (let i = 0; i < revokingAuthHis.length; i++) {
    await state.revokeAuth(revokingAuthHis[i]);
  }
  for (let i = 0; i < revokingClaimRevNonces.length; i++) {
    await state.revokeClaim(revokingClaimRevNonces[i]);
  }
  const newUserState = state.getIdenState();
  const challenge = getZidenParams().hasher([bitsToNum(oldUserState), bitsToNum(newUserState)]);
  const signature = await signChallenge(privateKey, challenge);

  return {
    userID: bitsToNum(userID),
    oldUserState: bitsToNum(oldUserState),
    newUserState: bitsToNum(newUserState),
    isOldStateGenesis,
    userAuthsRoot: rootsMatchProof.authsRoot,
    userAuthMtp: authExistsProof.authMTP,
    userAuthHi: auth.authHi,
    userAuthPubX: auth.pubKey.X,
    userAuthPubY: auth.pubKey.Y,
    userClaimsRoot: rootsMatchProof.claimsRoot,
    userClaimRevRoot: rootsMatchProof.claimRevRoot,
    challengeSignatureR8x: signature.challengeSignatureR8x,
    challengeSignatureR8y: signature.challengeSignatureR8y,
    challengeSignatureS: signature.challengeSignatureS,
  };
}

/**
 * update user state with Signature and HiHv-Claim
 * @category stateTransition
 * @async
 * @param {SignedChallenge} signature signature
 * @param {Auth} auth authClaim
 * @param {State} state userState
 * @param {Array<Auth>} insertingAuths AuthClaim array will be added
 * @param {Array.<{ArrayLike<number>, ArrayLike<number>}>} insertingClaimHiHvs Claims array will be added
 * @param {Array<BigInt>} revokingAuthHis AuthClaim array will be revoke (using Hi)
 * @param {Array<BigInt>} revokingClaimRevNonces Claim array will be revoke (using revoke nonces)
 * @returns {Promise<StateTransitionWitness>} State Transition Witness proof
 */
export async function stateTransitionWitnessWithSignatureAndHiHvs(
  signature: SignedChallenge,
  auth: Auth,
  state: State,
  insertingAuths: Array<Auth>,
  insertingClaimHiHvs: Array<[ArrayLike<number>, ArrayLike<number>]>,
  revokingAuthHis: Array<BigInt>,
  revokingClaimRevNonces: Array<BigInt>
): Promise<StateTransitionWitness> {
  const userID = state.userID;
  const oldUserState = state.getIdenState();
  const isOldStateGenesis = userID.subarray(2, 31).equals(oldUserState.subarray(-29)) ? 1 : 0;
  const authExistsProof = await state.generateAuthExistsProof(auth.authHi);
  const rootsMatchProof = await state.generateRootsMatchProof();
  for (let i = 0; i < insertingAuths.length; i++) {
    await state.insertAuth(insertingAuths[i]);
  }
  await state.batchInsertClaimByHiHv(insertingClaimHiHvs);
  for (let i = 0; i < revokingAuthHis.length; i++) {
    await state.revokeAuth(revokingAuthHis[i]);
  }
  for (let i = 0; i < revokingClaimRevNonces.length; i++) {
    await state.revokeClaim(revokingClaimRevNonces[i]);
  }
  const newUserState = state.getIdenState();

  return {
    userID: bitsToNum(userID),
    oldUserState: bitsToNum(oldUserState),
    newUserState: bitsToNum(newUserState),
    isOldStateGenesis,
    userAuthsRoot: rootsMatchProof.authsRoot,
    userAuthMtp: authExistsProof.authMTP,
    userAuthHi: auth.authHi,
    userAuthPubX: auth.pubKey.X,
    userAuthPubY: auth.pubKey.Y,
    userClaimsRoot: rootsMatchProof.claimsRoot,
    userClaimRevRoot: rootsMatchProof.claimRevRoot,
    challengeSignatureR8x: signature.challengeSignatureR8x,
    challengeSignatureR8y: signature.challengeSignatureR8y,
    challengeSignatureS: signature.challengeSignatureS,
  };
}
