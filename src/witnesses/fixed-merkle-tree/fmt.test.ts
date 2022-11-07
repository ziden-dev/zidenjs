import { buildFMTHashFunction, buildHash0Hash1, buildHasher, buildSnarkField, SnarkField } from '../../global';
import MerkleTree from './FixedMerkleTree';
// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { HashFunction } from './index';

describe('Test and benchmark Fixed Merkle Tree', () => {
  let fmt: MerkleTree;
  let hashFunction: HashFunction;
  let elements: BigInt[];
  let F: SnarkField;
  it('build params', async () => {
    F = await buildSnarkField();
    const hasher = await buildHasher();
    const hs = buildHash0Hash1(hasher, F);
    hashFunction = buildFMTHashFunction(hs.hash0, F);
    elements = [];
    for (let i = 0; i < 1 << 10; i++) {
      elements.push(BigInt(i));
    }
  });
  it('build FMT', () => {
    fmt = new MerkleTree(10, elements, hashFunction, F.toObject(F.zero));
  });

  let witness: {
    leaf: BigInt;
    root: BigInt;
    path2_root: BigInt[];
    path2_root_pos: number[];
  };
  it('Generate FMT witness', () => {
    const proof = fmt.proof(BigInt(10));
    witness = {
      leaf: BigInt(10),
      root: proof.pathRoot,
      path2_root: proof.pathElements,
      path2_root_pos: proof.pathIndices,
    };
  });
  it('Test Merkle Proof is valid', async () => {
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'fixed-merkle-tree', 'circom_test', 'merkleProof.circom')
    );
    const w = await circuit.calculateWitness(witness, true);
    await circuit.assertOut(w, { out: 1 });
  });
  it('test merkle proof for right most leaf', async () => {
    let values: Array<BigInt> = [];
    for (let i = 0; i < 1000; i++) {
      values.push(BigInt(123 * i));
    }
    const valueArraySize = 1 << 10;
    const sortedValues = values.sort();
    const biggestValue = sortedValues[values.length - 1];
    for (let i = values.length; i < valueArraySize; i++) {
      sortedValues.push(biggestValue);
    }
    const fmt = new MerkleTree(10, sortedValues, hashFunction, F.toObject(F.zero));
    const proof = fmt.proof(sortedValues[sortedValues.length - 1], sortedValues.length - 1);
    witness = {
      leaf: sortedValues[sortedValues.length - 1],
      root: proof.pathRoot,
      path2_root: proof.pathElements,
      path2_root_pos: proof.pathIndices,
    };
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'fixed-merkle-tree', 'circom_test', 'merkleProof.circom')
    );
    const w = await circuit.calculateWitness(witness, true);
    await circuit.assertOut(w, { out: 1 });
  });
});
