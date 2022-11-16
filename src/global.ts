import bigInt from 'big-integer';
// @ts-ignore
import { Scalar, getCurveFromName } from 'ffjavascript';
// @ts-ignore
import { buildPoseidon, buildEddsa } from 'circomlibjs';
import { HashFunction } from './witnesses/fixed-merkle-tree/index.js';

export const SNARK_SIZE: bigInt.BigNumber = bigInt(
  Scalar.fromString('21888242871839275222246405745257275088548364400416034343698204186575808495617')
);

export interface ZidenParams {
  readonly hasher: Hasher;
  readonly hash0: Hash0;
  readonly hash1: Hash1;
  readonly fmtHash: HashFunction;
  readonly eddsa: EDDSA;
  readonly F: SnarkField;
}
export type Hasher = (arr: Array<BigInt | ArrayLike<number>>) => ArrayLike<number>;
export type Hash0 = (left: BigInt | ArrayLike<number>, right: BigInt | ArrayLike<number>) => ArrayLike<number>;
export type Hash1 = (key: BigInt | ArrayLike<number>, value: BigInt | ArrayLike<number>) => ArrayLike<number>;
export interface SnarkField {
  toObject: (arr: ArrayLike<number>) => BigInt;
  e: (num: BigInt | ArrayLike<number> | number | string) => ArrayLike<number>;
  one: ArrayLike<number>;
  zero: ArrayLike<number>;
  eq: (value1: ArrayLike<number>, value2: ArrayLike<number>) => boolean;
  isZero: (value: ArrayLike<number>) => boolean;
  toString: (value: ArrayLike<number>) => string;
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

export function buildFMTHashFunction(hash0: Hash0, F: SnarkField): HashFunction {
  return function (left, right) {
    const temp = hash0(left, right);
    return F.toObject(temp);
  };
}

declare global {
  var zidenParams: ZidenParams;
}

export function getZidenParams(): ZidenParams {
  let params: ZidenParams;
  try {
    //@ts-ignore
    params = window.zidenParams;
  } catch (err) {
    params = global.zidenParams;
  }
  return params;
}

export async function setupParams() {
  const F = await buildSnarkField();
  const hasher = await buildPoseidon();
  const { hash0, hash1 } = buildHash0Hash1(hasher, F);
  const fmtHash = buildFMTHashFunction(hash0, F);
  const eddsa = await buildSigner();

  const params: ZidenParams = {
    hasher,
    hash0,
    hash1,
    eddsa,
    fmtHash,
    F,
  };

  try {
    // @ts-ignore
    window.zidenParams = params;
  } catch (err) {
    global.zidenParams = params;
  }
}
