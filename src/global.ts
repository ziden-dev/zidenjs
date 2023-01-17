import { buildPoseidon } from './crypto/poseidon_wasm.js';
import { HashFunction } from './witnesses/fixed-merkle-tree/index.js';
import buildEddsa from './crypto/eddsa.js';
import { getCurveFromName } from './crypto/ffjavascript.js';
import { Hash0, Hash1, Hasher, SnarkField, ZidenParams } from './index.js';



export async function buildHasher(): Promise<Hasher> {
  return await buildPoseidon();
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
  const bn128 = await getCurveFromName('bn128', true);
  const F = bn128.Fr;
  const hasher = await buildPoseidon();
  const { hash0, hash1 } = buildHash0Hash1(hasher, F);
  const fmtHash = buildFMTHashFunction(hash0, F);
  const eddsa = await buildEddsa(F);

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
