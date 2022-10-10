import bigInt from 'big-integer';
import { SNARK_SIZE, Hasher, SnarkField } from '../global.js';
import { bitsToNum, bufferArrayToHex, hexToBufferArray, numToBits } from '../utils.js';
/*
Claim structure

Index:
 i_0: [ 128  bits ] claim schema
      [ 32 bits ] option flags
          [3] Subject:
            000: A.1 Self
            001: invalid
            010: A.2.i OtherIden Index
            011: A.2.v OtherIden Value
            100: B.i Object Index
            101: B.v Object Value
          [1] Expiration: bool
          [1] Updatable: bool
          [27] 0
      [ 32 bits ] version (optional?)
      [ 32 bits ] claim seed
      [ 29 bits ] 0 - reserved for future use
 i_1: [ 248 bits] identity (case b) (optional)
      [  5 bits ] 0
 i_2: [ 253 bits] 0
 i_3: [ 253 bits] 0
Value:
 v_0: [ 64 bits ]  revocation nonce
      [ 64 bits ]  expiration date (optional)
      [ 125 bits] 0 - reserved
 v_1: [ 248 bits] identity (case c) (optional)
      [  5 bits ] 0
 v_2: [ 253 bits] 0
 v_3: [ 253 bits] 0
*/

const ErrDataOverflow = new Error('data does not fits SNARK size');
const ErrIncorrectIDPosition = new Error('incorrect ID position');
const ErrInvalidSubjectPosition = new Error('invalid subject position');
const ErrInvalidSchemaHash = new Error('invalid schema hash');
const ErrInvalidSlotIndex = new Error('invalid slot index');
const SchemaHashLength = 16;

/**
 * Check schema hash has correct length of 16 bytes
 * throw an error if schema hash has not length of 16
 * @param {Buffer} schemaHash schema hash in bytes representation
 */
export function checkSchemaHashLength(schemaHash: Buffer) {
  if (schemaHash.length !== SchemaHashLength) {
    throw ErrInvalidSchemaHash;
  }
}

// /**
//  * Represent schemahash in hex
//  * @param {Buffer} schemaHash schema hash in bytes representation
//  * @returns {string} schema hash in hex representation
//  */
// function schemaHashToHex(schemaHash) {
//   return utils.bytesToHex(schemaHash);
// }

// /**
//  * creates new SchemaHash from hex string
//  * @param {string} hex schema hash in hex representation
//  * @returns {Buffer} schema hash in bytes representation
//  */
// function schemaHashFromHex(hex) {
//   let result = Buffer.alloc(SchemaHashLength, 0);
//   let hashBytes = utils.hexToBytes(hex);
//   if (hashBytes.length > SchemaHashLength) {
//     throw ErrInvalidSchemaHash;
//   }
//   hashBytes.copy(result, 0, SchemaHashLength - hashBytes.length);
//   return result;
// }

/**
 * creates new SchemaHash from BigInt
 * @param {BigInt} num schema hash in BigInt representation
 * @returns {Buffer} schema hash in bytes representation
 */
export function schemaHashFromBigInt(num: BigInt): Buffer {
  return numToBits(num.valueOf(), SchemaHashLength);
}

/**
 * Represent schemahash in BigInt
 * @param {Buffer} schemaHash schema hash in bytes representation
 * @returns {BigInt} schema hash in BigInt representation
 */
export function schemaHashToBigInt(schemaHash: Buffer): BigInt {
  return bitsToNum(schemaHash);
}

// Option to create entry
export type Option = (entry: Entry) => void;
/**
 * Create entry with flag updatable
 * @param {boolean} val flag updatable
 * @return {Option}
 */
export function withFlagUpdatable(val: boolean): Option {
  return function (entry: Entry) {
    entry.setFlagUpdatable(val);
  };
}

/**
 * Create entry with flag expirable
 * @param {boolean} val flag expirable
 * @return {Option}
 */
export function withFlagExpirable(val: boolean): Option {
  return function (entry: Entry) {
    entry.setFlagExpirable(val);
  };
}

/**
 * Create entry with version
 * @param {BigInt} version
 * @return {Option}
 */
export function withVersion(version: BigInt): Option {
  return function (entry: Entry) {
    entry.setVersion(version);
  };
}

/**
 * Create entry with other ID stored in index
 * @param {Buffer} id other ID
 * @return {Option}
 */
export function withIndexID(id: Buffer): Option {
  return function (entry: Entry) {
    entry.setIndexID(id);
  };
}

/**
 * Create entry with other ID stored in value
 * @param {Buffer} id other ID
 * @return {Option}
 */
export function withValueID(id: Buffer): Option {
  return function (entry: Entry) {
    entry.setValueID(id);
  };
}

/**
 * Create entry with other ID stored in IDPosition
 * @param {Buffer} id other ID
 * @param {number} pos IDPosition
 * @return {Option}
 */
export function withID(id: Buffer, pos: number): Option {
  return function (entry: Entry) {
    switch (pos) {
      case IDPosition.IDPositionIndex: {
        entry.setIndexID(id);
        break;
      }
      case IDPosition.IDPositionValue: {
        entry.setValueID(id);
        break;
      }
      default: {
        throw ErrIncorrectIDPosition;
      }
    }
  };
}

/**
 * Create entry with revocation nonce
 * @param {BigInt} nonce revocation nonce
 * @return {Option}
 */
export function withRevocationNonce(nonce: BigInt): Option {
  return function (entry: Entry) {
    entry.setRevocationNonce(nonce);
  };
}

/**
 * Create entry with expiration date
 * @param {BigInt} date expiration date
 * @return {Option}
 */
export function withExpirationDate(date: BigInt): Option {
  return function (entry: Entry) {
    entry.setExpirationDate(date);
  };
}

/**
 * Create entry with index data
 * @param {Buffer} slotA data for slot index A
 * @param {Buffer} slotB data for slot index B
 * @return {Option}
 */
export function withIndexData(slotA: Buffer, slotB: Buffer): Option {
  return function (entry: Entry) {
    entry.setIndexData(slotA, slotB);
  };
}

/**
 * Create entry with value data
 * @param {Buffer} slotA data for slot value A
 * @param {Buffer} slotB data for slot value B
 * @return {Option}
 */
export function withValueData(slotA: Buffer, slotB: Buffer): Option {
  return function (entry: Entry) {
    entry.setValueData(slotA, slotB);
  };
}

/**
 * Create entry with slot data
 * @param {number} index index of slot
 * @param {Buffer} data data for slot
 * @return {Option}
 */
export function withSlotData(index: number, data: Buffer): Option {
  return function (entry: Entry) {
    entry.setSlotData(index, data);
  };
}

const EntryElemsLen = 8;
const SubjectFlag = {
  SubjectFlagSelf: 0,
  SubjectFlagOtherIdenIndex: 2,
  SubjectFlagOtherIdenValue: 3,
};

const IDPosition = {
  // IDPositionNone means ID value not located in claim.
  IDPositionNone: 0,
  // IDPositionIndex means ID value is in index slots.
  IDPositionIndex: 1,
  // IDPositionValue means ID value is in value slots.
  IDPositionValue: 2,
};

const FlagByteIndex = 16;
const FlagExpirableBitIndex = 3;
const FlagUpdatableBitIndex = 4;

/**
 * Check element in big endian must be less than claim element field
 * @param {Buffer} elem - elem in big endian
 * @throws {Error} throws an error when the check fails
 */
export function checkElemFitsClaim(elem: Buffer) {
  const elemBigInt = bigInt(bitsToNum(elem).valueOf());
  if (elemBigInt.greaterOrEquals(SNARK_SIZE)) {
    throw ErrDataOverflow;
  }
}

/**
 * Generic representation of claim elements
 * Entry element structure is as follows: |element 0|element 1|element 2|element 3|
 * Each element contains 253 useful bits enclosed on a 256 bits Buffer
 */
export class Entry {
  //elements: Array<Buffer>;
  _elements;
  /**
   * construct new entry from elements
   * @param {Array<Buffer>} elements
   */
  constructor(elements: Array<Buffer>) {
    if (elements.length != 8) {
      throw new Error('Elements length must be 8');
    }
    for (let i = 0; i < 8; i++) {
      checkElemFitsClaim(elements[i]);
    }
    this._elements = elements;
  }

  /**
   * Bytes representation of claim
   * @returns {Array<Buffer>} elements
   */
  get elements(): Array<Buffer> {
    return this._elements;
  }
  /**
   * Initialize claim elements with BigInt elements
   * @param {Array<BigInt>} elements
   */
  static newEntryFromBigints(elements: Array<BigInt>) {
    return new Entry(
      elements.map((e) => {
        const elemBits = numToBits(e, 32);
        checkElemFitsClaim(elemBits);
        return elemBits;
      })
    );
  }

  /**
   * Initialize claim elements with empty buffer
   */
  static newEmpty() {
    return new Entry([
      Buffer.alloc(32),
      Buffer.alloc(32),
      Buffer.alloc(32),
      Buffer.alloc(32),
      Buffer.alloc(32),
      Buffer.alloc(32),
      Buffer.alloc(32),
      Buffer.alloc(32),
    ]);
  }

  /**
   * Hash index calculation
   * Hash index is calculated from: elements 0,1,2,3
   * @param {Hasher} hasher
   * @returns {ArrayLike<number>} Hash index of the claim element structure
   */
  hiRaw(hasher: Hasher): ArrayLike<number> {
    const hashArray = this._elements.slice(0, 4).map((e) => bitsToNum(e));
    return hasher(hashArray);
  }

  /**
   * Hash index calculation
   * Hash index is calculated from: elements 0,1,2,3
   * @param {Hasher} hasher
   * @param {SnarkField} F
   * @returns {BigInt} Hash index of the claim element structure
   */
  hi(hasher: Hasher, F: SnarkField): BigInt {
    return F.toObject(this.hiRaw(hasher));
  }

  /**
   * Hash value calculation
   * Hash value is calculated from: elements 0,1,2,3
   * @param {Hasher} hasher
   * @returns {ArrayLike<number>} Hash value of the claim element structure
   */

  hvRaw(hasher: Hasher): ArrayLike<number> {
    const hashArray = this._elements.slice(4).map((e) => bitsToNum(e));
    return hasher(hashArray);
  }

  /**
   * Hash value calculation
   * Hash value is calculated from: elements 0,1,2,3
   * @param {Hasher} hasher
   * @param {SnarkField} F
   * @returns {BigInt} Hash value of the claim element structure
   */

  hv(hasher: Hasher, F: SnarkField): BigInt {
    return F.toObject(this.hvRaw(hasher));
  }

  /**
   * Hash value calculation
   * Hash value is calculated from: hi|hv
   * @param {Hasher} hasher
   * @param {SnarkField} F
   * @returns {BigInt} Hash value of the claim element structure
   */
  getClaimHash(hasher: Hasher, F: SnarkField): BigInt {
    return F.toObject(hasher([this.hi(hasher, F), this.hv(hasher, F)]));
  }

  /**
   * SetFlagUpdatable sets claim's flag `updatable`
   * @param {boolean} val updatable flag
   */
  setFlagUpdatable(val: boolean) {
    if (val) {
      this._elements[0][FlagByteIndex] |= 1 << (7 - FlagUpdatableBitIndex);
    } else {
      this._elements[0][FlagByteIndex] &= ~(1 << (7 - FlagUpdatableBitIndex));
    }
  }

  /**
   * GetFlagUpdatable returns claim's flag `updatable`
   * @returns {boolean} updatable flag
   */
  getFlagUpdatable(): boolean {
    let mask = 1 << (7 - FlagUpdatableBitIndex);
    return (this._elements[0][FlagByteIndex] & mask) > 0;
  }

  /**
   * SetFlagExpirable sets claim's flag `expirable`
   * @param {boolean} val expirable flag
   */
  setFlagExpirable(val: boolean) {
    if (val) {
      this._elements[0][FlagByteIndex] |= 1 << (7 - FlagExpirableBitIndex);
    } else {
      this._elements[0][FlagByteIndex] &= ~(1 << (7 - FlagExpirableBitIndex));
    }
  }

  /**
   * GetFlagExpirable returns claim's flag `expirable`
   * @returns {boolean} expiable flag
   */
  getFlagExpirable(): boolean {
    let mask = 1 << (7 - FlagExpirableBitIndex);
    return (this._elements[0][FlagByteIndex] & mask) > 0;
  }

  /**
   * SetSchemaHash updates claim's schema hash.
   * @param {Buffer} schemaHash schema hash
   */
  setSchemaHash(schemaHash: Buffer) {
    checkSchemaHashLength(schemaHash);
    schemaHash.copy(this._elements[0]);
  }

  /**
   * GetSchemaHash return claim's schema hash.
   * @returns {Buffer} schema hash
   */
  getSchemaHash(): Buffer {
    let schemaHash = Buffer.alloc(16, 0);
    this._elements[0].copy(schemaHash);
    return schemaHash;
  }

  /**
   * SetSubjectFlag updates claim's subject flag.
   * @param {Buffer} subjectFlag subject flag
   */
  setSubjectFlag(subjectFlag: Buffer) {
    this._elements[0][FlagByteIndex] &= 0b00011111;
    this._elements[0][FlagByteIndex] |= subjectFlag[0];
  }

  /**
   * GetSubjectFlag return claim's subject flag.
   * @returns {Buffer} subjectFlag subject flag
   */
  getSubjectFlag(): Buffer {
    let flag = Buffer.alloc(1);
    this._elements[0].copy(flag, 0, FlagByteIndex);
    flag[0] &= 0b11100000;
    return flag;
  }

  /**
   * GetClaimFlags return claim's 32 bits of flag.
   * @returns {Array<number>} claimFlags
   */
  getClaimFlags(): Array<number> {
    let flags = Buffer.alloc(4);
    this._elements[0].copy(flags, 0, FlagByteIndex);
    let flagBits = [];
    for (let i = 0; i < 4; i++) {
      let flagByte = flags[i];
      for (let j = 0; j < 8; j++) {
        if ((flagByte & (1 << (7 - j))) > 0) {
          flagBits.push(1);
        } else {
          flagBits.push(0);
        }
      }
    }
    return flagBits;
  }

  /**
   * GetIDPosition returns the position at which the ID is stored.
   * @returns {number} Id position
   */
  getIDPosition(): number {
    switch (parseInt(bitsToNum(this.getSubjectFlag()).toString())) {
      case SubjectFlag.SubjectFlagSelf: {
        return IDPosition.IDPositionNone;
      }
      case SubjectFlag.SubjectFlagOtherIdenIndex: {
        return IDPosition.IDPositionIndex;
      }
      case SubjectFlag.SubjectFlagOtherIdenValue: {
        return IDPosition.IDPositionValue;
      }
      default: {
        throw ErrInvalidSubjectPosition;
      }
    }
  }

  /**
   * SetVersion updates claim's version.
   * @param {BigInt} version 4 bytes
   */
  setVersion(version: BigInt) {
    const versionBytes = numToBits(version, 4);
    versionBytes.copy(this._elements[0], 20);
  }

  /**
   * GetVersion return claim's version.
   * @returns {BigInt} version
   */
  getVersion(): BigInt {
    const versionBytes = Buffer.alloc(4, 0);
    this._elements[0].copy(versionBytes, 0, 20, 24);
    return bitsToNum(versionBytes);
  }

  /**
   * SetIndexID return claim's version.
   * @param {Buffer} id other id
   */
  setIndexID(id: Buffer) {
    checkElemFitsClaim(id);
    this.resetValueID();
    this.setSubjectFlag(numToBits(BigInt(SubjectFlag.SubjectFlagOtherIdenIndex), 1));
    checkElemFitsClaim(id);
    id.copy(this._elements[1]);
  }

  /**
   * GetIndexID get claim's other index stored in index 1 slot.
   * @returns {Buffer} other id
   */
  getIndexID(): Buffer {
    let id = Buffer.alloc(31);
    this._elements[1].copy(id);
    return id;
  }

  /**
   * ResetIndexID clear index 1 slot.
   */
  resetIndexID() {
    this._elements[1] = Buffer.alloc(32);
  }

  /**
   * SetValueID return claim's version.
   * @param {Buffer} id other id
   */
  setValueID(id: Buffer) {
    checkElemFitsClaim(id);
    this.resetIndexID();
    this.setSubjectFlag(numToBits(BigInt(SubjectFlag.SubjectFlagOtherIdenValue), 1));
    checkElemFitsClaim(id);
    id.copy(this._elements[5]);
  }

  /**
   * GetValueID get claim's other value stored in value 1 slot.
   * @returns {Buffer} other id
   */
  getValueID(): Buffer {
    const id = Buffer.alloc(31);
    this._elements[5].copy(id);
    return id;
  }

  /**
   * ResetValueID clear value 1 slot.
   */
  resetValueID() {
    this._elements[5] = Buffer.alloc(32);
  }

  /**
   * ResetID clear value 1 slot and index 1 slot.
   */
  resetID() {
    this.resetIndexID();
    this.resetValueID();
    this.setSubjectFlag(numToBits(BigInt(SubjectFlag.SubjectFlagSelf), 1));
  }

  /**
   * GetID get claim's other id.
   * @returns {Buffer} other id
   */
  getID(): Buffer {
    switch (parseInt(bitsToNum(this.getSubjectFlag()).toString())) {
      case SubjectFlag.SubjectFlagOtherIdenIndex: {
        return this.getIndexID();
      }
      case SubjectFlag.SubjectFlagOtherIdenValue: {
        return this.getValueID();
      }
      default: {
        return Buffer.alloc(32);
      }
    }
  }

  /**
   * SetRevocationNonce set claim's revocation nonce
   * @param {BigInt} nonce 8 bytes
   */
  setRevocationNonce(nonce: BigInt) {
    const nonceBytes = numToBits(nonce, 8);
    nonceBytes.copy(this._elements[4]);
  }

  /**
   * GetRevocationNonce returns claim's revocation nonce
   * @returns {BigInt} nonce 8 bytes
   */
  getRevocationNonce(): BigInt {
    const nonceBytes = Buffer.alloc(8);
    this._elements[4].copy(nonceBytes);
    return bitsToNum(nonceBytes);
  }

  /**
   * set claim seed
   * @param {BigInt} seed
   */
  setClaimSeed(seed: BigInt) {
    const seedBits = numToBits(seed, 4);
    seedBits.copy(this._elements[0], 24);
  }

  /**
   * get claim seed
   * @returns {BigInt} claim seed
   */
  getClaimSeed(): BigInt {
    const seedBits = this._elements[0].subarray(24, 28);
    return bitsToNum(seedBits);
  }
  /**
   * SetExpirationDate set claim's expiration date
   * @param {BigInt} date 8 bytes represent in unix time
   */
  setExpirationDate(date: BigInt) {
    const dateBytes = numToBits(date, 8);
    dateBytes.copy(this._elements[4], 8);
  }

  /**
   * ResetExpirationDate clear claim's expiration date
   */
  resetExpirationDate() {
    const nonDate = Buffer.alloc(8);
    nonDate.copy(this._elements[4], 8);
  }

  /**
   * GetRevocationNonce returns claim's expiration date
   * @returns {BigInt} nonce 8 bytes
   */
  getExpirationDate(): BigInt {
    const dateBytes = Buffer.alloc(8);
    this._elements[4].copy(dateBytes, 0, 8);
    return bitsToNum(dateBytes);
  }

  /**
   * SetIndexData set claim's index slot A, B
   * @param {Buffer} slotA data stored in slot index A
   * @param {Buffer} slotB data stored in slot index B
   */
  setIndexData(slotA: Buffer, slotB: Buffer) {
    checkElemFitsClaim(slotA);
    checkElemFitsClaim(slotB);
    slotA.copy(this._elements[2]);
    slotB.copy(this._elements[3]);
  }

  /**
   * SetValueData set claim's value slot A, B
   * @param {Buffer} slotA data stored in slot value A
   * @param {Buffer} slotB data stored in slot value B
   */
  setValueData(slotA: Buffer, slotB: Buffer) {
    checkElemFitsClaim(slotA);
    checkElemFitsClaim(slotB);
    slotA.copy(this._elements[6]);
    slotB.copy(this._elements[7]);
  }

  /**
   * SetSlotData set claim's slot data
   * @param {number} index slot index
   * @param {Buffer} data data stored in slot at index
   */
  setSlotData(index: number, data: Buffer) {
    checkElemFitsClaim(data);
    if (!(index in [2, 3, 6, 7])) {
      throw ErrInvalidSlotIndex;
    }
    data.copy(this._elements[index]);
  }

  /**
   * GetSlotData get claim's slot data
   * @param {number} index slot index
   * @returns {Buffer} data data stored in slot at index
   */
  getSlotData(index: number): Buffer {
    if (index < 0 || index >= EntryElemsLen) {
      throw ErrInvalidSlotIndex;
    }
    const result = Buffer.alloc(32);
    this._elements[index].copy(result);
    return result;
  }

  /**
   * GetDataForCircuit return all claim's slot data in String representation
   * @returns {Array<String>} data data stored in slot at index
   */
  getDataForCircuit(): Array<BigInt> {
    return this._elements.map((e) => bitsToNum(e));
  }

  /**
   * Compare to other claim
   * @param {Entry} other
   * @returns {boolean} is 2 claims equal
   */
  equals(other: Entry): boolean {
    for (let i = 0; i < EntryElemsLen; i++) {
      if (!this._elements[i].equals(other.elements[i])) {
        return false;
      }
    }
    return true;
  }
  /**
   * convert claim to hex representation
   * @returns {string} hex
   */
  toHex(): string {
    return bufferArrayToHex(this._elements);
  }

  /**
   * construct new claim from hex representation
   * @param {string} hex
   */
  static async newClaimFromHex(hex: string) {
    const elements = hexToBufferArray(hex, 32);
    return new Entry(elements);
  }
}

/**
 * build new Claim with custom informations
 * @param {Buffer} schemaHash
 * @param {Option[]} options custom information to build entry
 * @returns {Entry} new entry
 */
export function newClaim(schemaHash: Buffer, ...options: Option[]): Entry {
  const entry = Entry.newEmpty();
  options.map((option) => option(entry));
  entry.setSchemaHash(schemaHash);
  return entry;
}
