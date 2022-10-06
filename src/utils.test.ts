import chai from "chai";
import { bitsToNum, bufferArrayToHex, bufferToHex, hexToBuffer, hexToBufferArray, hexToString, numToBits, privateKeyFromPassword, stringToHex } from './utils.js';

const {expect} = chai;

describe("[util] convert", () => {
    it("convert buffer - bigint", () => {
        const bi = BigInt(0x12abcdef)
        const buff = numToBits(bi, 4);
        console.log(buff);
        const bi_1 = bitsToNum(buff);
        console.log(bi)
        console.log(bi_1);
    });
    it("convert buffer - hex", () => {
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
        for(let i = 0; i< buff1.length; i++){
            expect(buffs1[i].equals(buffs[i])).to.be.true;
        }
    });
    it("convert string-hex", () => {
        const str = "Tran Duy Nhat";
        const hex = stringToHex(str);
        const str1 = hexToString(hex);
        expect(str === str1).to.be.true;
    });
    it("convert string to private key", () => {
        const password = "0xnhattranduy";
        const privateKey = privateKeyFromPassword(password);
        console.log(privateKey)
    });
});
