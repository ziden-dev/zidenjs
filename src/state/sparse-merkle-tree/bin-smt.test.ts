import path from 'path';
// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import { BinSMT } from './bin-smt.js';
import { expect } from 'chai';
import { getZidenParams, setupParams } from '../../global.js';
import { SMTLevelDb } from '../../db/index.js';
import { Primitive } from './index.js';

async function testInclusion(tree: BinSMT, _key: Primitive, circuit: any) {
  let F = getZidenParams().F
  const key = F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.true;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
  while (siblings.length < 10) siblings.push(0);

  const w = await circuit.calculateWitness(
    {
      enabled: 1,
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

async function testExclusion(tree: BinSMT, _key: Primitive, circuit: any) {
  let F = getZidenParams().F;
  const key = F.e(_key);
  const res = await tree.find(key);

  expect(res.found).to.be.false;

  let siblings: (BigInt | number)[] = [];
  for (let i = 0; i < res.siblings.length; i++) siblings.push(F.toObject(res.siblings[i]));
  while (siblings.length < 10) siblings.push(0);

  const w = await circuit.calculateWitness({
    enabled: 1,
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
  let tree: BinSMT;

  before(async () => {
    await setupParams();
    circuit = await wasm_tester(path.join('src', 'state', 'circom_test', 'smt.circom'));
    const db = new SMTLevelDb('src/db_test/smt_test');
    tree = new BinSMT(db, getZidenParams().F.zero,10);
  });
  it('Benchmark insert into smt', async () => {
    await tree.insert(8, 88);
    await tree.insert(32, 3232);
    await tree.insert(7, 77);
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

  it('Test delete a leaf', async () => {
    await tree.delete(7);
    await testExclusion(tree, 7, circuit);
  });

  it('Test update a leaf', async () => {
    await tree.update(8, 11);
    const f = await tree.find(getZidenParams().F.e(8));
    expect(getZidenParams().F.toObject(f.foundValue!)).to.be.equal(BigInt(11));
    await testInclusion(tree, 8, circuit);
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
    const db = new SMTLevelDb('src/db_test/smt_test_1');
    const tree = new BinSMT(db, getZidenParams().F.zero, 10);
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
