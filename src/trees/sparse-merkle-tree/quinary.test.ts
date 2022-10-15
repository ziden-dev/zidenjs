// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';

describe('Test quinary-decimal converter', () => {
  let circuit: any;
  it('setup circuit', async () => {
    circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'dec2quin.circom'));
  });
  it('test decimal to quinary', async () => {
    const expected_output = [1, 2, 3, 4, 0, 2, 3, 4, 1, 1];
    let input = BigInt(0);
    let e5 = BigInt(1);
    for (let i = 0; i < 10; i++) {
      input += e5 * BigInt(expected_output[i]);
      e5 *= BigInt(5);
    }
    const w = await circuit.calculateWitness({ in: input }, true);
    await circuit.assertOut(w, { out: expected_output });
  });
});
