import { getZidenParams } from '../global.js';
import { Auth, EDDSAPublicKey, SignedChallenge } from '../index.js';

/**
 * Generate new eddsa public key from private key
 * @category State
 * @param {Buffer} privateKey private key
 * @returns {Promise<EDDSAPublicKey>} eddsa public key
 */
export function newEDDSAPublicKeyFromPrivateKey(privateKey: Buffer): EDDSAPublicKey {
  const pubkey = getZidenParams().eddsa.prv2pub(privateKey);
  const pubkeyX = getZidenParams().F.toObject(pubkey[0]);
  const pubkeyY = getZidenParams().F.toObject(pubkey[1]);
  return {
    X: pubkeyX,
    Y: pubkeyY,
  };
}

/**
 * Create authClaim from private key
 * @category State
 * @param {Buffer} privateKey private key
 * @returns Object include authHi and pubKey
 */
export function newAuthFromPrivateKey(privateKey: Buffer): Auth {
  const pubKey = newEDDSAPublicKeyFromPrivateKey(privateKey);
  return {
    authHi: BigInt(0),
    pubKey,
  };
}

export function hashPublicKey(pubkey: EDDSAPublicKey): ArrayLike<number> {
  return getZidenParams().hasher([pubkey.X, pubkey.Y]);
}

/**
 * Sign challenge with private key
 * @category State
 * @param {Buffer} privateKey
 * @param {BigInt} challenge
 * @returns {Promise<SignedChallenge>} signature
 */
export async function signChallenge(
  privateKey: Buffer,
  challenge: BigInt | ArrayLike<number> | number
): Promise<SignedChallenge> {
  const msg = getZidenParams().F.e(challenge);
  const signature = getZidenParams().eddsa.signPoseidon(privateKey, msg);
  return {
    challenge: getZidenParams().F.toObject(msg),
    challengeSignatureR8x: getZidenParams().F.toObject(signature.R8[0]),
    challengeSignatureR8y: getZidenParams().F.toObject(signature.R8[1]),
    challengeSignatureS: signature.S,
  };
}
