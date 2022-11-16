// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { getZidenParams, setupParams } from '../../global.js';

describe('Test quinary hasher', () => {
  let circuit: any;
  it('setup params', async () => {
    await setupParams();
    circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'quinHasher.circom'));
  }).timeout(10000);
  it('test quinary hashing', async () => {
    const siblings = [100, 101, 102, 103];
    const child = 199;
    const index = 3;

    const hasher_input = siblings.slice();
    hasher_input.splice(index, 0, child);
    const expected_output = getZidenParams().F.toObject(
      getZidenParams().hasher(hasher_input.map((e) => getZidenParams().F.e(e)))
    );
    const w = await circuit.calculateWitness({ siblings, index, child }, true);
    await circuit.assertOut(w, { out: expected_output });
  }).timeout(10000);

  it('test quinary hashing for big number', async () => {
    const siblings = [
      BigInt('109304834343412432'),
      BigInt('1093048343439912432'),
      BigInt('509304834343412432'),
      BigInt('309304834343412432'),
    ];
    const child = BigInt('8348409237047');
    const index = 2;

    const hasher_input = siblings.slice();
    hasher_input.splice(index, 0, child);
    const expected_output = getZidenParams().F.toObject(
      getZidenParams().hasher(hasher_input.map((e) => getZidenParams().F.e(e)))
    );
    const w = await circuit.calculateWitness({ siblings, index, child }, true);
    await circuit.assertOut(w, { out: expected_output });
  }).timeout(10000);
});
