import { Entry, newClaim, withIndexData, schemaHashFromBigInt } from './entry.js';
import { numToBits } from '../utils.js';
import { getZidenParams } from '../global.js';

/**
 * Generate new auth claim from private key
 * @param {Buffer} privateKey
 * @returns {Promise<Entry>} auth claim
 */
export async function newAuthClaimFromPrivateKey(privateKey: Buffer): Promise<Entry> {
  const pubkey = getZidenParams().eddsa.prv2pub(privateKey);
  const pubkeyX = getZidenParams().F.toObject(pubkey[0]);
  const pubkeyY = getZidenParams().F.toObject(pubkey[1]);
  const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861770'));
  const authClaim = newClaim(schemaHash, withIndexData(numToBits(pubkeyX, 32), numToBits(pubkeyY, 32)));
  return authClaim;
}

/**
 * Generate new auth claim from public key
 * @param {BigInt} pubkeyX
 * @param {BigInt} pubkeyY
 * @returns {Promise<Entry>} auth claim
 */
 export async function newAuthClaimFromPublicKey(pubkeyX: BigInt, pubkeyY: BigInt): Promise<Entry> {
  const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861770'));
  const authClaim = newClaim(schemaHash, withIndexData(numToBits(pubkeyX, 32), numToBits(pubkeyY, 32)));
  return authClaim;
}

export interface SignedChallenge {
  readonly challenge: BigInt;
  readonly challengeSignatureR8x: BigInt;
  readonly challengeSignatureR8y: BigInt;
  readonly challengeSignatureS: BigInt;
}
/**
 * Sign challenge with private key
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
