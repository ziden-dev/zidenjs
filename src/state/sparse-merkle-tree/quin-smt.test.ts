import path from 'path';
// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import { QuinSMT } from './quin-smt.js';
import { expect } from 'chai';
import { getZidenParams, setupParams, SnarkField } from '../../global.js';
import { SMTLevelDb } from '../../db/index.js';
import { Primitive } from './index.js';

async function testInclusion(tree: QuinSMT, _key: Primitive, circuit: any) {
  let F = getZidenParams().F;
  const key = F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.true;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
  while (siblings.length < 14 * 4) siblings.push(0);

  const w = await circuit.calculateWitness(
    {
      fnc: 0,
      root: F.toObject(tree.root),
      siblings: siblings,
      oldKey: 0,
      oldValue: 0,
      isOld0: 0,
      key: F.toObject(key),
      value: F.toObject(res.foundValue!),
    },
    true
  );

  await circuit.checkConstraints(w);
}

async function testExclusion(tree: QuinSMT, _key: Primitive, circuit: any) {
  let F = getZidenParams().F;
  const key = F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.false;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
  while (siblings.length < 14 * 4) siblings.push(0);

  const w = await circuit.calculateWitness({
    fnc: 1,
    root: F.toObject(tree.root),
    siblings: siblings,
    oldKey: res.isOld0 ? 0 : F.toObject(res.notFoundKey!),
    oldValue: res.isOld0 ? 0 : F.toObject(res.notFoundValue!),
    isOld0: res.isOld0 ? 1 : 0,
    key: F.toObject(key),
    value: 0,
  });

  await circuit.checkConstraints(w);
}

describe('SMT Verifier test', function () {
  let circuit: any;
  let tree: QuinSMT;
  let F: SnarkField;
  it('setup params', async () => {
    await setupParams();
    F = getZidenParams().F;
    circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'quin_smt.circom'));

    const db = new SMTLevelDb('src/trees/db_test/quin_smt_test');
    tree = new QuinSMT(db, F.zero, 14);
  }).timeout(10000);

  it('Benchmark insert into quin merkle tree', async () => {
    await tree.insert(7, 77);
    await tree.insert(8, 88);
    await tree.insert(32, 111);
  });

  it('Test find an existing leaf', async () => {
    const f1 = await tree.find(F.e(7));
    expect(f1.found).to.be.true;

    const f2 = await tree.find(F.e(8));
    expect(f2.found).to.be.true;
    expect(F.toObject(f2.foundValue!) === BigInt(88)).to.be.true;

    const f3 = await tree.find(F.e(32));
    expect(f3.found).to.be.true;

    await tree.update(8, 99);
    const f4 = await tree.find(F.e(8));
    expect(f4.found).to.be.true;
    expect(F.toObject(f4.foundValue!) === BigInt(99)).to.be.true;
  });

  it('Test find a leaf which does not exist', async () => {
    const f1 = await tree.find(F.e(9));
    expect(f1.found).to.be.false;

    const f2 = await tree.find(F.e(10));
    expect(f2.found).to.be.false;

    const f3 = await tree.find(F.e(11));
    expect(f3.found).to.be.false;

    await tree.delete(7);
    const f4 = await tree.find(F.e(7));
    expect(f4.found).to.be.false;
  });
  it('Check inclussions in a tree', async () => {
    await tree.insert(7, 100);
    await tree.insert(100, 191);
    await tree.insert(1000, 101);

    await testInclusion(tree, 7, circuit);
    await testInclusion(tree, 8, circuit);
    await testInclusion(tree, 32, circuit);
    await testInclusion(tree, 100, circuit);
    await testInclusion(tree, 1000, circuit);
  });

  it('Check inclussions of a oversize leaf', async () => {
    const leaf = (BigInt(1) << BigInt(252)) + BigInt(139);
    await tree.insert(leaf, 1010);
    await testInclusion(tree, leaf, circuit);
  });

  it('Check exclussions in a tree', async () => {
    await testExclusion(tree, 0, circuit);
    await testExclusion(tree, 6, circuit);
    await testExclusion(tree, 9, circuit);
    await testExclusion(tree, 33, circuit);
    await testExclusion(tree, 31, circuit);
    await testExclusion(tree, 16, circuit);
    await testExclusion(tree, 64, circuit);
  });
});
