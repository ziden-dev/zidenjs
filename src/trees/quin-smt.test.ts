import path from 'path';
// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import { Primitive, QuinSMT } from './quin-smt.js';
import { expect } from 'chai';
import { buildHash0Hash1, buildHasher, buildSnarkField, Hash1, Hasher, SnarkField } from '../global.js';
import { SMTLevelDb } from '../db/index.js';

async function testInclusion(tree: QuinSMT, _key: Primitive, circuit: any) {
  const key = tree.F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.true;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(tree.F.toObject(res.siblings[i]));
  while (siblings.length < 14) siblings.push(0);

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

async function testExclusion(tree: QuinSMT, _key: Primitive, circuit: any) {
  const key = tree.F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.false;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(tree.F.toObject(res.siblings[i]));
  while (siblings.length < 14) siblings.push(0);

  const w = await circuit.calculateWitness({
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
  let tree: QuinSMT;
  let hasher: Hasher;
  let hash1: Hash1;

  it("setup params", async () => {
    circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'quin_smt.circom'));

    F = await buildSnarkField();
    hasher = await buildHasher();
    const hs = buildHash0Hash1(hasher, F);
    hash1 = hs.hash1;
    const db = new SMTLevelDb('src/trees/db_test/quin_smt_test', F);
    tree = new QuinSMT(db, F.zero, hasher, hash1, F, 14);
    
  }).timeout(10000);

  it('Benchmark insert into quin merkle tree', async () => {
    await tree.insert(7, 77);
    //await tree.insert(8, 88);
  })
  it.skip('Check inclussion in a tree of 3', async () => {
    await testInclusion(tree, 7, circuit);
    await testInclusion(tree, 8, circuit);
    await testInclusion(tree, 32, circuit);
  });

  it.skip('Check exclussion in a tree of 3', async () => {
    await testExclusion(tree, 0, circuit);
    await testExclusion(tree, 6, circuit);
    await testExclusion(tree, 9, circuit);
    await testExclusion(tree, 33, circuit);
    await testExclusion(tree, 31, circuit);
    await testExclusion(tree, 16, circuit);
    await testExclusion(tree, 64, circuit);
  });
});
