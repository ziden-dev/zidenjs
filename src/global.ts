import bigInt from 'big-integer';
// @ts-ignore
import { Scalar, getCurveFromName } from 'ffjavascript';
// @ts-ignore
import { buildPoseidon, buildEddsa } from 'circomlibjs';

export const SNARK_SIZE: bigInt.BigNumber = bigInt(
  Scalar.fromString('21888242871839275222246405745257275088548364400416034343698204186575808495617')
);

export type Hasher = (arr: Array<BigInt | ArrayLike<number>>) => ArrayLike<number>;
export type Hash0 = (left: BigInt | ArrayLike<number>, right: BigInt | ArrayLike<number>) => ArrayLike<number>;
export type Hash1 = (key: BigInt | ArrayLike<number>, value: BigInt | ArrayLike<number>) => ArrayLike<number>;
export interface SnarkField {
  toObject: (arr: ArrayLike<number>) => BigInt;
  e: (num: BigInt | ArrayLike<number> | number) => ArrayLike<number>;
  one: ArrayLike<number>;
  zero: ArrayLike<number>;
}
export interface EDDSASignature {
  R8: Array<ArrayLike<number>>;
  S: BigInt;
}
export interface EDDSA {
  prv2pub: (privateKey: Buffer) => Array<ArrayLike<number>>;
  signPoseidon: (privateKey: Buffer, msg: ArrayLike<number>) => EDDSASignature;
}
export async function buildSnarkField(): Promise<SnarkField> {
  const bn128 = await getCurveFromName('bn128', true);
  return bn128.Fr;
}

export async function buildHasher(): Promise<Hasher> {
  return await buildPoseidon();
}

export async function buildSigner(): Promise<EDDSA> {
  return await buildEddsa();
}

export function buildHash0Hash1(hasher: Hasher, F: SnarkField): { hash0: Hash0; hash1: Hash1 } {
  return {
    hash0: function (left, right) {
      return hasher([left, right]);
    },
    hash1: function (key, value) {
      return hasher([key, value, F.one]);
    },
  };
}
