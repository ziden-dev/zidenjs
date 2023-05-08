import { expect } from 'chai';
import path from 'path';
import {
  newClaim,
  withExpirationDate,
  withFlagUpdatable,
  withFlagExpirable,
  withIndexData,
  withValueData,
  withRevocationNonce,
  withID,
  schemaHashFromBigInt,
  Entry,
} from './claim/entry.js';

// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import { bitsToNum } from './utils.js';
import { setupParams } from './global.js';

describe('test entries', async () => {
  let claim: Entry;
  let schemaHash: Buffer;

  it('setup params', async () => {
    await setupParams();
  }).timeout(10000);

  it('test create entry with custom information', async () => {
    schemaHash = schemaHashFromBigInt(BigInt('1234'));
    const expirationDate = BigInt(123456);
    const revocationNonce = BigInt(111);
    const expirableFlag = true;
    const updatableFlag = false;
    const otherID = Buffer.alloc(31, 1);
    const indexAData = Buffer.alloc(31, 2);
    const indexBData = Buffer.alloc(31, 3);
    const valueAData = Buffer.alloc(31, 4);
    const valueBData = Buffer.alloc(31, 5);
    claim = newClaim(
      schemaHash,
      withExpirationDate(expirationDate),
      withRevocationNonce(revocationNonce),
      withFlagExpirable(expirableFlag),
      withFlagUpdatable(updatableFlag),
      withID(otherID, 1),
      withIndexData(indexAData, indexBData),
      withValueData(valueAData, valueBData)
    );

    expect(claim.getExpirationDate()).to.be.equal(expirationDate);
    expect(claim.getRevocationNonce()).to.be.equal(revocationNonce);
    expect(claim.getFlagExpirable()).to.be.equal(expirableFlag);
    expect(claim.getFlagUpdatable()).to.be.equal(updatableFlag);
    expect(claim.getSubjectFlag()[0]).to.be.equal(0b01000000);
    expect(claim.getID().equals(otherID)).to.be.true;
  });

  it('test getClaimSchema circuit', async () => {
    const claimCircuit = claim.getDataForCircuit();
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getClaimSchema.circom'));
    const w = await circuit.calculateWitness(
      {
        claim: claimCircuit,
      },
      true
    );
    await circuit.assertOut(w, { schema: bitsToNum(schemaHash) });
  });

  it('test getClaimHiHv circuit', async () => {
    const claimCircuit = claim.getDataForCircuit();

    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'claimHiHv.circom'));
    const w = await circuit.calculateWitness(
      {
        claim: claimCircuit,
      },
      true
    );
    await circuit.assertOut(w, {
      hi: claim.hi(),
      hv: claim.hv(),
    });
  });

  it('test getClaimHash circuit', async () => {
    const claimCircuit = claim.getDataForCircuit();
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getClaimHash.circom'));
    const w = await circuit.calculateWitness(
      {
        claim: claimCircuit,
      },
      true
    );
    await circuit.assertOut(w, {
      hash: claim.getClaimHash(),
      hi: claim.hi(),
      hv: claim.hv(),
    });
  }).timeout(10000);

  it('test getClaimRevNonce circuit', async () => {
    const claimCircuit = claim.getDataForCircuit();
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getClaimRevNonce.circom'));
    const w = await circuit.calculateWitness(
      {
        claim: claimCircuit,
      },
      true
    );
    await circuit.assertOut(w, { revNonce: claim.getRevocationNonce() });
  });

  it('test getClaimExpiration circuit', async () => {
    const claimCircuit = claim.getDataForCircuit();
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getClaimExpiration.circom'));
    const w = await circuit.calculateWitness(
      {
        claim: claimCircuit,
      },
      true
    );
    await circuit.assertOut(w, { expiration: claim.getExpirationDate() });
  });

  it('test getClaimHeader circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getClaimHeader.circom'));
    const claimCircuit = claim.getDataForCircuit();

    const w = await circuit.calculateWitness(
      {
        claim: claimCircuit,
      },
      true
    );
    await circuit.assertOut(w, {
      claimType: bitsToNum(schemaHash),
      claimFlags: claim.getClaimFlags(),
    });
  });

  it('test getSubjectLocation circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getSubjectLocation.circom'));

    const w = await circuit.calculateWitness(
      {
        claimFlags: claim.getClaimFlags(),
      },
      true
    );
    await circuit.assertOut(w, { out: 2 });
  });

  it('test isExpirable circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'isExpirable.circom'));

    const w = await circuit.calculateWitness(
      {
        claimFlags: claim.getClaimFlags(),
      },
      true
    );
    await circuit.assertOut(w, { out: 1 });
  });

  it('test isUpdatable circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'isUpdatable.circom'));

    const w = await circuit.calculateWitness(
      {
        claimFlags: claim.getClaimFlags(),
      },
      true
    );
    await circuit.assertOut(w, { out: 0 });
  });

  it('test getValueByIndex circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getValueByIndex.circom'));
    const claimCircuit = claim.getDataForCircuit();
    for (let i = 0; i < 8; i++) {
      const w = await circuit.calculateWitness(
        {
          claim: claimCircuit,
          index: i,
        },
        true
      );

      await circuit.assertOut(w, {
        value: claimCircuit[i],
      });
    }
  }).timeout(10000);

  it('test getClaimSubjectOtherIden circuit', async () => {
    const claimCircuit = claim.getDataForCircuit();
    const circuit = await wasm_tester(path.join('src', 'claim', 'circom_test', 'getClaimSubjectOtherIden.circom'));
    const w = await circuit.calculateWitness(
      {
        claim: claimCircuit,
      },
      true
    );

    await circuit.assertOut(w, { id: bitsToNum(claim.getID()) });
  });

  it('convert claim to hex string', async () => {
    const hex = claim.toHex();
    console.log(hex);
    const claim1 = await Entry.newClaimFromHex(hex);
    expect(claim.equals(claim1)).to.be.true;
  });
});
