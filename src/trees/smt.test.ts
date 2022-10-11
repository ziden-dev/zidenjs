import path from 'path';
// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import { Primitive, SMT } from './smt.js';
import { expect } from 'chai';
import { buildHash0Hash1, buildHasher, buildSnarkField, Hash0, Hash1, SnarkField } from '../global.js';
import { SMTLevelDb } from '../db/index.js';

async function testInclusion(tree: SMT, _key: Primitive, circuit: any) {
  const key = tree.F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.true;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(tree.F.toObject(res.siblings[i]));
  while (siblings.length < 10) siblings.push(0);

  const w = await circuit.calculateWitness(
    {
      enabled: 1,
      fnc: 0,
      root: tree.F.toObject(tree.root),
      siblings: siblings,
      oldKey: 0,
      oldValue: 0,
      isOld0: 0,
      key: tree.F.toObject(key),
      value: tree.F.toObject(res.foundValue!),
    },
    true
  );

  await circuit.checkConstraints(w);
}

async function testExclusion(tree: SMT, _key: Primitive, circuit: any) {
  const key = tree.F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.false;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(tree.F.toObject(res.siblings[i]));
  while (siblings.length < 10) siblings.push(0);

  const w = await circuit.calculateWitness({
    enabled: 1,
    fnc: 1,
    root: tree.F.toObject(tree.root),
    siblings: siblings,
    oldKey: res.isOld0 ? 0 : tree.F.toObject(res.notFoundKey!),
    oldValue: res.isOld0 ? 0 : tree.F.toObject(res.notFoundValue!),
    isOld0: res.isOld0 ? 1 : 0,
    key: tree.F.toObject(key),
    value: 0,
  });

  await circuit.checkConstraints(w);
}

describe('SMT Verifier test', function () {
  let F: SnarkField;
  let circuit: any;
  let tree: SMT;
  let hash0: Hash0;
  let hash1: Hash1;
  this.timeout(100000);

  before(async () => {
    circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'smt.circom'));

    F = await buildSnarkField();
    const hasher = await buildHasher();
    const hs = buildHash0Hash1(hasher, F);
    hash0 = hs.hash0;
    hash1 = hs.hash1;
    const db = new SMTLevelDb('src/trees/db_test/smt_test', F);
    tree = new SMT(db, F.zero, hash0, hash1, F, 10);
    await tree.insert(7, 77);
    await tree.insert(8, 88);
    await tree.insert(32, 3232);
  });

  it('Check inclussion in a tree of 3', async () => {
    await testInclusion(tree, 7, circuit);
    await testInclusion(tree, 8, circuit);
    await testInclusion(tree, 32, circuit);
  });

  it('Check exclussion in a tree of 3', async () => {
    await testExclusion(tree, 0, circuit);
    await testExclusion(tree, 6, circuit);
    await testExclusion(tree, 9, circuit);
    await testExclusion(tree, 33, circuit);
    await testExclusion(tree, 31, circuit);
    await testExclusion(tree, 16, circuit);
    await testExclusion(tree, 64, circuit);
  });

  it('Check not enabled accepts any thing', async () => {
    let siblings: (BigInt | number)[] = [];
    for (let i = 0; i < 10; i++) siblings.push(i);

    const w = await circuit.calculateWitness({
      enabled: 0,
      fnc: 0,
      root: 1,
      siblings: siblings,
      oldKey: 22,
      oldValue: 33,
      isOld0: 0,
      key: 44,
      value: 0,
    });

    await circuit.checkConstraints(w);
  });

  it('check collision resistant', async () => {
    const db = new SMTLevelDb('src/trees/db_test/smt_test_1', F);
    const tree = new SMT(db, F.zero, hash0, hash1, F, 10);
    await tree.insert(1, 1);
    await tree.insert(2, 1);
    try {
      await tree.insert(1025, 1);
      throw new Error('Insert function should throw an error');
    } catch (err) {
      expect((err as Error).message).to.be.equal('Reached SMT max level');
    }
  });
});
