import { Entry, newClaim, withIndexData, schemaHashFromBigInt } from './entry.js';
import { numToBits } from '../utils.js';
import { EDDSA, SnarkField } from '../global.js';

/**
 * Generate new auth claim from private key
 * @param {EDDSA} eddsa
 * @param {SnarkField} F
 * @param {Buffer} privateKey
 * @returns {Promise<Entry>} auth claim
 */
export async function newAuthClaimFromPrivateKey(eddsa: EDDSA, F: SnarkField, privateKey: Buffer): Promise<Entry> {
  const pubkey = eddsa.prv2pub(privateKey);
  const pubkeyX = F.toObject(pubkey[0]);
  const pubkeyY = F.toObject(pubkey[1]);
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
 * Sign challenge with private
 * @param {EDDSA} eddsa
 * @param {SnarkField} F
 * @param {Buffer} privateKey
 * @param {BigInt} challenge
 * @returns {Promise<SignedChallenge>} signature
 */
export async function signChallenge(
  eddsa: EDDSA,
  F: SnarkField,
  privateKey: Buffer,
  challenge: BigInt | ArrayLike<number> | number
): Promise<SignedChallenge> {
  const msg = F.e(challenge);
  const signature = eddsa.signPoseidon(privateKey, msg);
  return {
    challenge: F.toObject(msg),
    challengeSignatureR8x: F.toObject(signature.R8[0]),
    challengeSignatureR8y: F.toObject(signature.R8[1]),
    challengeSignatureS: signature.S,
  };
}
