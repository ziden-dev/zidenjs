// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import path from 'path';
import crypto from 'crypto';

import { newAuthClaimFromPrivateKey } from '../claim/auth-claim.js';
import {
  newClaim,
  schemaHashFromBigInt,
  withIndexData,
  withExpirationDate,
  Entry,
  withSlotData,
} from '../claim/entry.js';
import { SMTLevelDb } from '../db/level_db.js';
import { Trees } from '../trees/trees.js';
import { StateTransitionWitness, stateTransitionWitness, stateTransitionWitnessWithHiHv } from './stateTransition.js';
import { setupParams } from '../global.js';

describe('test state transition with binary merkle tree', async () => {
  let privateKey: Buffer;
  let authClaim: Entry;
  let claimsDb: SMTLevelDb;
  let authDb: SMTLevelDb;
  let trees: Trees;
  let claim1: Entry;
  let claim2: Entry;
  let claim3: Entry;
  let claim4: Entry;
  let claim5: Entry;
  let claim6: Entry;
  let claim7: Entry;

  let auth1: Entry;
  let auth2: Entry;
  let auth3: Entry;
  let auth4: Entry;
  let circuitCheck: (witness: StateTransitionWitness) => Promise<void>;
  it('set up trees and claims', async () => {
    await setupParams();
    privateKey = Buffer.alloc(32, 1);

    authClaim = await newAuthClaimFromPrivateKey(privateKey);

    auth1 = await newAuthClaimFromPrivateKey(crypto.randomBytes(32));
    auth2 = await newAuthClaimFromPrivateKey(crypto.randomBytes(32));
    auth3 = await newAuthClaimFromPrivateKey(crypto.randomBytes(32));
    auth4 = await newAuthClaimFromPrivateKey(crypto.randomBytes(32));

    claimsDb = new SMTLevelDb('src/witnesses/db_test/state_db/claims');
    authDb = new SMTLevelDb('src/witnesses/db_test/state_db/auth');

    trees = await Trees.generateID([authClaim], claimsDb, authDb);

    claim1 = newClaim(
      schemaHashFromBigInt(BigInt('12345')),
      withSlotData(7, Buffer.alloc(30, 2)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim2 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim3 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 3), Buffer.alloc(30, 4)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim4 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 4), Buffer.alloc(30, 5)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim5 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 5), Buffer.alloc(30, 6)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim6 = newClaim(
      schemaHashFromBigInt(BigInt('579832')),
      withIndexData(Buffer.alloc(10, 10), Buffer.alloc(30, 10)),
      withExpirationDate(BigInt(Date.now() + 200000))
    );
    claim7 = newClaim(
      schemaHashFromBigInt(BigInt('579832')),
      withIndexData(Buffer.alloc(10, 11), Buffer.alloc(30, 10)),
      withExpirationDate(BigInt(Date.now() + 200000))
    );

    circuitCheck = async (witness: StateTransitionWitness) => {
      const circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'bin', 'stateTransition.circom'));
      const w = await circuit.calculateWitness(witness, true);
      await circuit.checkConstraints(w);
    };
  }).timeout(100000);

  it('1st state transition', async () => {
    const w1 = await stateTransitionWitness(privateKey, authClaim, trees, [claim1], [auth1]);
    await circuitCheck(w1)
    await stateTransitionWitness(privateKey, authClaim, trees, [claim2, claim3], []);
  }).timeout(20000);

  it('2nd state transition', async () => {
    await stateTransitionWitness(
      privateKey,
      authClaim,
      trees,
      [claim4],
      []
    );
  });
  let witness: StateTransitionWitness;
  it('3rd state transition', async () => {
    witness = await stateTransitionWitness(privateKey, authClaim, trees, [claim5], [auth2, auth3]);
    console.log(witness.isOldStateGenesis);
  });

  it('test circuit constraint', async () => {
    await circuitCheck(witness);
  }).timeout(20000);

  it('4th state transition with hi-hv', async () => {
    const claim6HiHv: [ArrayLike<number>, ArrayLike<number>] = [claim6.hiRaw(), claim6.hvRaw()];
    const claim7HiHv: [ArrayLike<number>, ArrayLike<number>] = [claim7.hiRaw(), claim7.hvRaw()];
    witness = await stateTransitionWitnessWithHiHv(
      privateKey,
      authClaim,
      trees,
      [claim6HiHv, claim7HiHv],
      [auth4]
    );

    await circuitCheck(witness);
  }).timeout(100000);

  it('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/witnesses/circom_test/bin/stateTransition.wasm',
      'src/witnesses/circom_test/bin/stateTransition.zkey'
    );
  }).timeout(100000);
});
