// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { createMask, shiftValue, setBits } from '../utils.js';
import { createMerkleQueryInput, MerkleQueryInput } from './query.js';
import { OPERATOR } from '../index.js';
import { expect } from 'chai';
import { setupParams } from '../global.js';

describe('Test and benchmark query circuit', () => {
  it('setup params', async () => {
    await setupParams();
  });

  let slotValue: BigInt = BigInt(0);
  let value0: BigInt;
  let value1: BigInt;
  let value2: BigInt;

  let mask0: BigInt;
  let mask1: BigInt;
  let mask2: BigInt;

  it('setup slot value, masks for querying and test masking circuits', async () => {
    const valuePart0 = BigInt(1000); // 10 bits ~ 2 bytes
    const valuePart1 = BigInt((1 << 30) - 10); // 30 bits ~ 4 bytes
    const valuePart2 = BigInt(1) << (BigInt(127) - BigInt(3)); // 127 bits ~ 16 bytes

    slotValue = setBits(slotValue, 0, valuePart0);
    slotValue = setBits(slotValue, 10, valuePart1);
    slotValue = setBits(slotValue, 40, valuePart2);

    mask0 = createMask(0, 10);
    mask1 = createMask(10, 40);
    mask2 = createMask(40, 167);

    value0 = valuePart0;
    value1 = shiftValue(valuePart1, 10);
    value2 = shiftValue(valuePart2, 40);
    //console.log('mask0 = ', mask0);
    const circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'masking.circom'));

    const w0 = await circuit.calculateWitness(
      {
        mask: mask0,
        value: slotValue,
      },
      true
    );
    await circuit.assertOut(w0, { out: value0 });

    const w1 = await circuit.calculateWitness(
      {
        mask: mask1,
        value: slotValue,
      },
      true
    );
    await circuit.assertOut(w1, { out: value1 });

    const w2 = await circuit.calculateWitness(
      {
        mask: mask2,
        value: slotValue,
      },
      true
    );
    await circuit.assertOut(w2, { out: value2 });
  });

  interface QueryWitness extends MerkleQueryInput {
    in: BigInt;
    operator: number;
  }

  let inWitness: QueryWitness;
  let circuit;
  it('should pass IN operation query circuit', async () => {
    let values = [value1];
    for (let i = 0; i < 100; i++) {
      values.push(BigInt(101 * i));
    }
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.IN);
    inWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 4,
    };
    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(inWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);

  it('should not pass IN operation query circuit with invalid value', async () => {
    const fraudWitness = {
      ...inWitness,
      in: BigInt(101),
    };
    const circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));
    const circuitWrongErr = new Error('Something is wrong in query circuit');
    try {
      const w = await circuit.calculateWitness(fraudWitness, true);
      await circuit.assertOut(w, { out: 1 });
      throw circuitWrongErr;
    } catch (err) {
      expect(err !== undefined && err !== circuitWrongErr).to.be.true;
    }
  }).timeout(10000);

  let notInWitness: QueryWitness;
  it('should pass NOT IN operation query circuit in case attesting value is greater than the right most leaf', async () => {
    let values: Array<BigInt> = [];
    for (let i = 0; i < 1000; i++) {
      values.push(BigInt(123 * i));
    }
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.NOT_IN);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 5,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);

  it('should pass NOT IN operation query circuit in case attesting value is less than the left most leaf', async () => {
    let values: Array<BigInt> = [];
    for (let i = 0; i < 1000; i++) {
      values.push(value1.valueOf() + BigInt(123 * i + 1));
    }
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.NOT_IN);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 5,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);

  it('should pass NOT IN operation query circuit in case attesting value is between 2 consecutive leaves', async () => {
    let values: Array<BigInt> = [];
    for (let i = 0; i < 1000; i++) {
      values.push(value1.valueOf() + BigInt(123 * (i - 333) - 1));
    }
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.NOT_IN);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 5,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);
  it('should pass NOOP operation query circuit', async () => {
    let values: Array<BigInt> = [];
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.NOOP);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 0,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);
  it('should pass EQUAL operation query circuit', async () => {
    let values: Array<BigInt> = [value1];
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.EQUAL);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 1,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);
  it('should pass LESS THAN operation query circuit', async () => {
    let values: Array<BigInt> = [value1.valueOf() + BigInt(1)];
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.LESS_THAN);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 2,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);
  it('should pass GREATER THAN operation query circuit', async () => {
    let values: Array<BigInt> = [value1.valueOf() - BigInt(1)];
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.GREATER_THAN);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 3,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);
  it('should pass IN RANGE operation query circuit', async () => {
    let values: Array<BigInt> = [value1.valueOf() - BigInt(1), value1.valueOf() + BigInt(1)];
    let merkleQueryInput = createMerkleQueryInput(values, 10, value1, OPERATOR.IN_RANGE);
    notInWitness = {
      ...merkleQueryInput,
      in: value1,
      operator: 6,
    };

    circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'query.circom'));

    const w = await circuit.calculateWitness(notInWitness, true);
    await circuit.assertOut(w, { out: 1 });
  }).timeout(10000);
});
