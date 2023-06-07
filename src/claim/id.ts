import { getZidenParams } from '../global.js';
import { numToBits } from '../utils.js';
export const IDType = {
  Default: Buffer.from([0x00, 0x00]),
  ReadOnly: Buffer.from([0x00, 0x01]),
};
const ErrInvalidIDLength = new Error('ID length must be 31');
const ErrEmptyID = new Error('ID must not be empty');
// ID is a byte array with
// [  type  | root_genesis ]
// [2 bytes |   29 bytes ]
// where the root_genesis are the first 29 bytes from the hash root_genesis
const IDLength = 31;

/**
 * Generate ID from type, genesis
 * @category Claim ID
 * @param {Buffer} type
 * @param {Buffer} genesis
 * @returns {Buffer} id
 */
export function newID(type: Buffer, genesis: Buffer): Buffer {
  const id = Buffer.alloc(31);
  type.copy(id, 0, 0, 2);
  genesis.copy(id, 2);
  return id;
}

/**
 * Generate ID from BigInt
 * @category Claim ID
 * @param {BigInt} bigint
 * @returns {Buffer} id
 */
export function IDFromBigInt(bigint: BigInt): Buffer {
  const bytes = numToBits(bigint, 31);

  return IDFromBytes(bytes);
}

/**
 * Generate ID from bytes
 * @category Claim ID
 * @param {Buffer} bytes
 * @returns {Buffer} id
 */
export function IDFromBytes(bytes: Buffer): Buffer {
  if (bytes.length != IDLength) {
    throw ErrInvalidIDLength;
  }
  if (bytes.equals(Buffer.alloc(31))) {
    throw ErrEmptyID;
  }
  const id = Buffer.alloc(31);
  bytes.copy(id);
  return id;
}

/**
 * IdGenesisFromIdenState calculates the genesis ID from an Identity State.
 * @category Claim ID
 * @param {Buffer} idenState IdenState
 * @param {Buffer} type 2 bytes of id type
 * @returns {Buffer} id genesis
 */
export function IDGenesisFromIdenState(idenState: Buffer, type: Buffer): Buffer {
  const idGenesis = Buffer.alloc(29);

  idenState.copy(idGenesis, 0, idenState.length - 29);
  return newID(type, idGenesis);
}

/**
 * Generate Iden State from claim tree root, revocation root, root of roots
 * @category Claim ID
 * @param {BigInt} authsRoot auths tree root
 * @param {BigInt} claimsRoot claims tree root
 * @param {BigInt} authRevRoot auth rev root
 * @param {BigInt} claimRevRoot claim rev roots
 * @returns {ArrayLike<number>} idenState
 */
export function idenState(
  authsRoot: BigInt,
  claimsRoot: BigInt,
  //authRevRoot: BigInt,
  claimRevRoot: BigInt
): ArrayLike<number> {
  return getZidenParams().hasher([authsRoot, claimsRoot, claimRevRoot]);
}
