import { toBigIntBE, toBufferBE } from "bigint-buffer";
/**
 * Allocates a new Buffer from a bigInt number in little-endian format
 * @param {bigInt} number - bigInt number
 * @returns {Buffer} - Decoded Buffer
 */
export function numToBits(number: BigInt, width: number): Buffer {
  const buff = toBufferBE(number.valueOf(), width);
  return swapEndianness(buff);
}

/**
 * Allocates a new bigInt from a buffer in big-endian format
 * @param {Buffer} buff - Buffer to convert
 * @returns {BigInt} - Decoded bigInt
 */
export function bitsToNum(buff: Buffer): BigInt {
  const revBuff = swapEndianness(buff);
  return toBigIntBE(revBuff);
}
/**
 * Swap endianess buffer from big endian to little endian and vice versa
 * @param {Buffer} buff - Buffer to swap
 * @returns {Buffer} - Buffer swapped
 */
export function swapEndianness(buff: Buffer): Buffer {
  const len = buff.length;
  let buffSwap = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    buffSwap[i] = 0;
    for (let j = 0; j < 8; j++) {
      const bit = (buff[len - 1 - i] & (1 << j)) > 0;
      if (bit) {
        buffSwap[i] |= 1 << (7 - j);
      }
    }
  }
  return buffSwap;
}

/**
 * Convert buffer to hex string
 * @param {Buffer} buff
 * @returns {string}
 */
export function bufferToHex(buff: Buffer): string {
  return bitsToNum(buff).toString(16);
}

/**
 * Convert buffer array to hex string
 * @param {Array<Buffer>} buffs
 * @returns {string}
 */
export function bufferArrayToHex(buffs: Array<Buffer>): string {
  let result = buffs.reduce((result, buff) => {
    return result + bitsToNum(buff).toString(16) + "-";
  }, "");
  return result.slice(0, result.length - 1);
}

/**
 * Convert hex string to buffer
 * @param {string} hex
 * @param {number} width length of buffer
 * @returns {Buffer}
 */
export function hexToBuffer(hex: string, width: number): Buffer {
  if (!hex.startsWith("0x")) {
    hex = "0x" + hex;
  }
  return numToBits(BigInt(hex), width);
}

/**
 * Convert hex string to buffer array
 * @param {string} hex
 * @param {number} width length of buffer
 * @returns {Array<Buffer>}
 */
export function hexToBufferArray(hex: string, width: number): Array<Buffer> {
  const hexs = hex.split("-");
  return hexs.map((h) => hexToBuffer(h, width));
}

/**
 * Convert unicode string to hex representation
 * @param {string} str
 * @returns {string} hex
 */
export function stringToHex(str: string): string {
  var hex = "";
  for (var i = 0; i < str.length; i++) {
    hex += "" + str.charCodeAt(i).toString(16);
  }
  hex = "0x" + hex;
  return hex;
}

/**
 * Convert hex representation to unicode string
 * @param {string} hex
 * @returns {string} str
 */
export function hexToString(hex: string): string {
  if (hex.startsWith("0x")) {
    hex = hex.slice(2);
  }
  var str = "";
  for (var i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
  }
  return str;
}

/**
 * Convert password to private key in bits representation
 * @param {string} password
 * @returns {Buffer} private key
 */
export function privateKeyFromPassword(password: string): Buffer {
  const privateKeyHex = stringToHex(password);
  return hexToBuffer(privateKeyHex, 32);
}

