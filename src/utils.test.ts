import chai from 'chai';
import { getCurveFromName } from './crypto/ffjavascript.js';
import {
  bitsToNum,
  bufferArrayToHex,
  bufferToFloat,
  bufferToHex,
  floatToBuffer,
  getPartialValue,
  hexToBuffer,
  hexToBufferArray,
  hexToString,
  numToBits,
  privateKeyFromPassword,
  setBits,
  stringToHex,
} from './utils.js';

const { expect } = chai;

describe('[util] convert', () => {
  it('import ff', async () => {
    const bn128 = await getCurveFromName('bn128', true);
    const F = bn128.Fr;
    console.log(F.e(1));
  });
  it('convert buffer - bigint', () => {
    const bi = BigInt(0x12abcdef);
    const buff = numToBits(bi, 4);
    console.log(buff);
    const bi_1 = bitsToNum(buff);
    console.log(bi);
    console.log(bi_1);
  });
  it('convert buffer - hex', () => {
    const buff = Buffer.from([0x12, 0x23]);
    const hex = bufferToHex(buff);
    console.log(hex);

    const buffs = [Buffer.from([0x12, 0x23]), Buffer.from([0x1f, 0x23]), Buffer.from([0x12, 0x2e])];
    const hexs = bufferArrayToHex(buffs);
    console.log(hexs);

    const buff1 = hexToBuffer(hex, 2);
    expect(buff.equals(buff1)).to.be.true;
    const buffs1 = hexToBufferArray(hexs, 2);
    expect(buffs1.length).to.be.equal(3);
    for (let i = 0; i < buff1.length; i++) {
      expect(buffs1[i].equals(buffs[i])).to.be.true;
    }
  });
  it('convert string-hex', () => {
    const str = 'Tran Duy Nhat';
    const hex = stringToHex(str);
    const str1 = hexToString(hex);
    expect(str === str1).to.be.true;
  });
  it('convert string to private key', () => {
    const password = '0xnhattranduy';
    const privateKey = privateKeyFromPassword(password);
    console.log(privateKey);
  });
  it('test get-set bits', () => {
    const bi = BigInt('1234341344174910744743147290');
    const value = BigInt('12348');
    const bi1 = setBits(bi, 5, value);
    const value1 = getPartialValue(bi1, 5, 5 + value.toString(2).length);
    expect(value).to.be.equal(value1);
  });
  it('test buffer - float64', () => {
    const f = 10.05;
    const floatToBuff = floatToBuffer(f);
    const buffToFloat = bufferToFloat(floatToBuff);
    expect(Math.abs(buffToFloat - f) < 1e-6).to.be.true;
  });
});
