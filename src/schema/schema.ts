import { getZidenParams } from '../global.js';
import {
  Entry,
  newClaim,
  schemaHashFromBigInt,
  withExpirationDate,
  withFlagExpirable,
  withFlagUpdatable,
  withID,
  withIndexData,
  withValueData,
} from '../claim/entry.js';
import {
  bitsToNum,
  bufferToFloat,
  bufferToHex,
  floatToBuffer,
  getPartialValue,
  hexToBuffer,
  numToBits,
  setBits,
  stringToHex,
} from '../utils.js';

export type Registry = {
  schemaHash?: string;
  issuerId?: string;
  description?: string;
  expiration?: number;
  updatable?: boolean;
  idPosition?: number;
  proofType?: string;
};

export type Schema = {
  title: string;
  properties: any;
  index: Array<string>;
  value: Array<string>;
  required: Array<string>;
};

/**
 * Generate entry from data, schema and registry
 * @param {any} data raw data of user
 * @param {Schema} schema schema form
 * @param {Registry} registry registry of issuer
 * @returns {Entry} Claim of data
 */
export function generateEntry(data: any, schema: Schema, registry: Registry): Entry {
  let id = data['userId'];
  if (id == undefined) {
    throw 'Required userId';
  }

  schema.index.forEach((element) => {
    let val = data[element];
    if (val == undefined) {
      throw 'Required ' + element;
    }
  });

  // userId
  let userId = hexToBuffer(id.toString(), 31);

  let indexSlot: Array<BigInt> = dataSlot(data, schema.index, schema.properties);
  let valueSlot: Array<BigInt> = dataSlot(data, schema.value, schema.properties);

  let claim = newClaim(
    schemaHashFromBigInt(BigInt(registry?.schemaHash ?? '123456')),
    withID(userId, registry?.idPosition ?? 1),
    withIndexData(numToBits(indexSlot[0], 32), numToBits(indexSlot[1], 32)),
    withValueData(numToBits(valueSlot[0], 32), numToBits(valueSlot[1], 32)),
    withFlagExpirable(true),
    withExpirationDate(BigInt(Date.now() + (registry?.expiration ?? 2592000000))),
    withFlagUpdatable(registry?.updatable ?? false)
  );

  return claim;
}

/**
 * convert entry to data
 * @param {Entry} entry Claim
 * @param {Schema} schema Schema form
 * @returns {any} object of raw data
 */
export function generateDataFromEntry(entry: Entry, schema: Schema): any {
  let data: any = {};
  data['userId'] = bufferToHex(entry.getID());
  let indexData: Array<BigInt> = [bitsToNum(entry.getSlotData(2)), bitsToNum(entry.getSlotData(3))];
  let valueData: Array<BigInt> = [bitsToNum(entry.getSlotData(6)), bitsToNum(entry.getSlotData(7))];
  let index = entryToData(indexData, schema.index, schema.properties);
  let value = entryToData(valueData, schema.value, schema.properties);

  for (let i in index) {
    data[i] = index[i];
  }

  for (let i in value) {
    data[i] = value[i];
  }

  return data;
}

function dataSlot(data: any, index: Array<string>, properties: any) {
  let ans: Array<BigInt> = [BigInt(0), BigInt(0)];
  let slotNumber = 0;
  let bitStart = 0;
  let bitEnd = 0;
  index.forEach((element) => {
    let property = properties[element];
    let value: BigInt = BigInt(0);
    switch (property['type']) {
      case 'string': // 127 bit
        bitEnd = bitStart + 126;
        let hashData = getZidenParams()
          .F.toObject(getZidenParams().hasher([BigInt(stringToHex(data[element] ?? ''))]))
          .toString(2);
        let bitRemove = hashData.length < 126 ? 0 : hashData.length - 126;
        let hashDataFixed = BigInt('0b' + hashData.slice(0, hashData.length - bitRemove));
        value = BigInt(hashDataFixed);
        break;
      case 'float': // 64 bit
        bitEnd = bitStart + 63;
        value = bitsToNum(floatToBuffer(data[element] ?? 0));
        break;
      case 'boolean': // 4 bit
        bitEnd = bitStart + 3;
        if (data[element]) {
          value = BigInt(1);
        } else {
          value = BigInt(0);
        }
        break;
      case 'date': // 32bit
        bitEnd = bitStart + 31;
        value = BigInt((data[element] ?? 0).toString());
        break;
      case 'datetime': // 48 bit
        bitEnd = bitStart + 47;
        value = BigInt((data[element] ?? 0).toString());
        break;
      case 'integer':
        let length = Math.ceil(Math.log2(property['maximum'] ?? 1));
        length = length + 8 - (length % 8);
        bitEnd = bitEnd + length - 1;
        value = BigInt((data[element] ?? 0).toString());
        break;
      default:
        throw 'Not have type: ' + property['type'] + ' in ' + element;
    }

    if (bitEnd > 253) {
      bitEnd = bitEnd - bitStart;
      bitStart = 0;
      slotNumber = 1;
    }
    ans[slotNumber] = setBits(ans[slotNumber], bitStart, value);
    bitStart = bitEnd + 1;
  });

  return ans;
}

function entryToData(slotData: Array<BigInt>, index: Array<string>, properties: any) {
  let ans: any = {};
  let slotNumber = 0;
  let bitStart = 0;
  let bitEnd = 0;
  index.forEach((element) => {
    let property = properties[element];
    switch (property['type']) {
      case 'string': // 126 bit
        bitEnd = bitStart + 126;
        break;
      case 'float': // 64 bit
        bitEnd = bitStart + 63;
        break;
      case 'boolean': // 4 bit
        bitEnd = bitStart + 3;
        break;
      case 'date': // 32bit
        bitEnd = bitStart + 31;
        break;
      case 'datetime': // 48 bit
        bitEnd = bitStart + 47;
        break;
      case 'integer':
        let length = Math.ceil(Math.log2(property['maximum'] ?? 1));
        length = length + 8 - (length % 8);
        bitEnd = bitEnd + length - 1;
        break;
      default:
        throw 'Not have type: ' + property['type'] + ' in ' + element;
    }

    if (bitEnd > 253) {
      bitEnd = bitEnd - bitStart;
      bitStart = 0;
      slotNumber = 1;
    }
    ans[element] = getPartialValue(slotData[slotNumber], bitStart, bitEnd);
    switch (property['type']) {
      case 'string': // 126 bit
        ans[element] = ans[element].toString();
        break;
      case 'float': // 64 bit
        ans[element] = bufferToFloat(numToBits(ans[element], 8));
        break;
      case 'boolean': // 4 bit
        ans[element] = ans[element] ? true : false;
        break;
      case 'date': // 32bit
        ans[element] = parseInt(ans[element].toString());
        break;
      case 'datetime': // 48 bit
        ans[element] = parseInt(ans[element].toString());
        break;
      case 'integer':
        ans[element] = parseInt(ans[element].toString());
        break;
      default:
        throw 'Not have type: ' + property['type'] + ' in ' + element;
    }

    bitStart = bitEnd + 1;
  });
  return ans;
}

/**
 *
 * @param {Schema} schema form schema
 * @returns {Array<any>} return properti slot of schema
 */
export function schemaPropertiesSlot(schema: Schema): Array<any> {
  let propertiesSlot: Array<any> = [];
  let indexSlot = propertiesToSlot(2, schema.index, schema.properties);
  let valueSlot = propertiesToSlot(6, schema.value, schema.properties);
  indexSlot.forEach((element) => {
    propertiesSlot.push(element);
  });

  valueSlot.forEach((element) => {
    propertiesSlot.push(element);
  });

  return propertiesSlot;
}

function propertiesToSlot(pos: number, index: Array<string>, properties: any) {
  let ans: Array<any> = [];
  let bitStart = 0;
  let bitEnd = 0;
  index.forEach((element) => {
    let property = properties[element];
    switch (property['type']) {
      case 'string': // 126 bit
        bitEnd = bitStart + 126;
        break;
      case 'float': // 64 bit
        bitEnd = bitStart + 63;
        break;
      case 'boolean': // 4 bit
        bitEnd = bitStart + 3;
        break;
      case 'date': // 32bit
        bitEnd = bitStart + 31;
        break;
      case 'datetime': // 48 bit
        bitEnd = bitStart + 47;
        break;
      case 'integer':
        let length = Math.ceil(Math.log2(property['maximum'] ?? 1));
        length = length + 8 - (length % 8);
        bitEnd = bitEnd + length - 1;
        break;
      default:
        throw 'Not have type: ' + property['type'] + ' in ' + element;
    }

    if (bitEnd > 253) {
      bitEnd = bitEnd - bitStart;
      bitStart = 0;
      pos = pos + 1;
    }

    ans.push({
      propertyName: element,
      propertyType: property['type'],
      slot: pos,
      begin: bitStart,
      end: bitEnd,
    });

    bitStart = bitEnd + 1;
  });

  return ans;
}

export function getSchemaHashFromSchema(schema: any): string {
  let hashData = getZidenParams()
    .F.toObject(getZidenParams().hasher([BigInt(stringToHex(JSON.stringify(schema)))]))
    .toString(2);
  let bitRemove = hashData.length < 128 ? 0 : hashData.length - 128;
  let hashDataFixed = BigInt('0b' + hashData.slice(0, hashData.length - bitRemove));
  let value = BigInt(hashDataFixed);
  return value.toString();
}

export function getHashString(val: string): BigInt {
  let hashData = getZidenParams()
          .F.toObject(getZidenParams().hasher([BigInt(stringToHex(val ?? ''))]))
          .toString(2);
  let bitRemove = hashData.length < 126 ? 0 : hashData.length - 126;
  let hashDataFixed = BigInt('0b' + hashData.slice(0, hashData.length - bitRemove));
  let value = BigInt(hashDataFixed);
  return value;
}