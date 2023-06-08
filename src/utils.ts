import { toBigIntBE, toBufferBE } from 'bigint-buffer';
/**
 * Allocates a new Buffer from a bigInt number in little-endian format
 * @category utils
 * @param {bigInt} number - bigInt number
 * @returns {Buffer} - Decoded Buffer
 */
export function numToBits(number: BigInt, width: number): Buffer {
  const buff = toBufferBE(number.valueOf(), width);
  return swapEndianness(buff);
}

/**
 * Allocates a new bigInt from a buffer in big-endian format
 * @category utils
 * @param {Buffer} buff - Buffer to convert
 * @returns {BigInt} - Decoded bigInt
 */
export function bitsToNum(buff: Buffer): BigInt {
  const revBuff = swapEndianness(buff);
  return toBigIntBE(revBuff);
}
/**
 * Swap endianess buffer from big endian to little endian and vice versa
 * @category utils
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
 * @category utils
 * @param {Buffer} buff
 * @returns {string}
 */
export function bufferToHex(buff: Buffer): string {
  return bitsToNum(buff).toString(16);
}

/**
 * Convert buffer array to hex string
 * @category utils
 * @param {Array<Buffer>} buffs
 * @returns {string}
 */
export function bufferArrayToHex(buffs: Array<Buffer>): string {
  let result = buffs.reduce((result, buff) => {
    return result + bitsToNum(buff).toString(16) + '-';
  }, '');
  return result.slice(0, result.length - 1);
}

/**
 * Convert hex string to buffer
 * @category utils
 * @param {string} hex
 * @param {number} width length of buffer
 * @returns {Buffer}
 */
export function hexToBuffer(hex: string, width: number): Buffer {
  if (!hex.startsWith('0x')) {
    hex = '0x' + hex;
  }
  return numToBits(BigInt(hex), width);
}

/**
 * Convert hex string to buffer array
 * @category utils
 * @param {string} hex
 * @param {number} width length of buffer
 * @returns {Array<Buffer>}
 */
export function hexToBufferArray(hex: string, width: number): Array<Buffer> {
  const hexs = hex.split('-');
  return hexs.map((h) => hexToBuffer(h, width));
}

/**
 * Convert unicode string to hex representation
 * @category utils
 * @param {string} str
 * @returns {string} hex
 */
export function stringToHex(str: string): string {
  var hex = '';
  for (var i = 0; i < str.length; i++) {
    hex += '' + str.charCodeAt(i).toString(16);
  }
  hex = '0x' + hex;
  return hex;
}

/**
 * Convert hex representation to unicode string
 * @category utils
 * @param {string} hex
 * @returns {string} str
 */
export function hexToString(hex: string): string {
  if (hex.startsWith('0x')) {
    hex = hex.slice(2);
  }
  var str = '';
  for (var i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
  }
  return str;
}

/**
 * Convert password to private key in bits representation
 * @category utils
 * @param {string} password
 * @returns {Buffer} private key
 */
export function privateKeyFromPassword(password: string): Buffer {
  const privateKeyHex = stringToHex(password);
  return hexToBuffer(privateKeyHex, 32);
}

/**
 * Compress timestamp (64 bits), claimSchema (128 bits), slotIndex (3 bits), operator (3 bits) into 1 input
 * @category utils
 * @param {BigInt} value value to mask
 * @param {number} bitsToShift
 * @returns {BigInt} masked attessting value
 */
export function shiftValue(value: BigInt, bitsToShift: number): BigInt {
  return value.valueOf() << BigInt(bitsToShift);
}

/**
 * Create bit mask for fragment query
 * @category utils
 * @param {number} from
 * @param {number} to
 * @returns {BigInt} masked attessting value
 */
export function createMask(from: number, to: number): BigInt {
  let mask = ''.padStart(256, '0').split('');
  for (let i = from; i < to; i++) {
    mask[i] = '1';
  }
  mask.reverse();
  return BigInt('0b' + mask.join(''));
}

/**
 * set bits of target bigint in range start from offset
 * @category utils
 * @param {BigInt} target target bigint we want to set bits
 * @param {number} offset offset to set bits
 * @param {BigInt} value value we want to set
 * @returns {BigInt} target value after setting bits
 */
export function setBits(target: BigInt, offset: number, value: BigInt): BigInt {
  const valueBits = value.toString(2).split('').reverse();
  if (valueBits.length + offset > 256) {
    throw new Error('Invalid value bits');
  }
  const targetBits = target.toString(2).padStart(256, '0').split('').reverse();
  for (let i = offset; i < valueBits.length + offset; i++) {
    targetBits[i] = valueBits[i - offset];
  }
  return BigInt('0b' + targetBits.reverse().join(''));
}

/**
 * get partial value of source bigint in range start from offset
 * @category utils
 * @param {BigInt} source position of slot we want to get bits
 * @param {number} from start offset to get bits
 * @param {number} to end offset to get bits
 * @returns {BigInt} value lie in range
 */
export function getPartialValue(source: BigInt, from: number, to: number): BigInt {
  const mask = createMask(from, to);
  return BigInt('0b' + (source.valueOf() & mask.valueOf()).toString(2).slice(0, to - from));
}

/**
 * Convert float64 to buffer
 * @category utils
 * @param {number} f float we want to convert to buffer
 * @returns {Buffer} value f in buffer
 */
export function floatToBuffer(f: number): Buffer {
  let buf = new ArrayBuffer(8);
  new Float64Array(buf)[0] = f;

  var buffer = Buffer.alloc(8);
  var view = new Uint8Array(buf);
  for (var i = 0; i < buffer.length; ++i) {
    buffer[i] = view[i];
  }

  return buffer;
}

/**
 * Convert Buffer to float64
 * @category utils
 * @param {Buffer} buffer buffer we want to convert to float
 * @returns {number} value of float
 */
export function bufferToFloat(buffer: Buffer): number {
  const buf = new ArrayBuffer(buffer.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }
  var float = new Float64Array(buf);
  return float[0];
}
