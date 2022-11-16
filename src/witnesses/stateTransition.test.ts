// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import path from 'path';

import { newAuthClaimFromPrivateKey } from '../claim/auth-claim.js';
import {
  newClaim,
  schemaHashFromBigInt,
  withIndexData,
  withExpirationDate,
  withValueData,
  withRevocationNonce,
  withVersion,
  Entry,
} from '../claim/entry.js';
import { IDType } from '../claim/id.js';
import { SMTLevelDb } from '../db/level_db.js';
import { SMTType, Trees } from '../trees/trees.js';
import { StateTransitionWitness, stateTransitionWitness, stateTransitionWitnessWithHiHv } from './stateTransition.js';
import { setupParams } from '../global.js';

describe('test authentication', async () => {
  let privateKey: Buffer;
  let authClaim: Entry;
  let claimsDb: SMTLevelDb;
  let revocationDb: SMTLevelDb;
  let rootsDb: SMTLevelDb;
  let trees: Trees;
  let claim1: Entry;
  let claim2: Entry;
  let claim3: Entry;
  let claim4: Entry;
  let claim5: Entry;
  let claim6: Entry;
  let claim7: Entry;
  let circuitCheck: (witness: StateTransitionWitness) => Promise<void>;
  it('set up trees and claims', async () => {
    await setupParams()
    privateKey = Buffer.alloc(32, 1);

    authClaim = await newAuthClaimFromPrivateKey(privateKey);
    claimsDb = new SMTLevelDb('src/witnesses/db_test/state_db/claims');
    revocationDb = new SMTLevelDb('src/witnesses/db_test/state_db/revocation');
    rootsDb = new SMTLevelDb('src/witnesses/db_test/state_db/roots');

    trees = await Trees.generateID(
      [authClaim],
      claimsDb,
      revocationDb,
      rootsDb,
      IDType.Default,
      32,
      SMTType.BinSMT
    );

    claim1 = newClaim(
      schemaHashFromBigInt(BigInt('12345')),
      withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 2)),
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
  }).timeout(10000);
  it('benchmark create claim', () => {
    newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 5), Buffer.alloc(30, 6)),
      withValueData(Buffer.alloc(30, 5), Buffer.alloc(30, 6)),
      withRevocationNonce(BigInt(100)),
      withVersion(BigInt(100)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
  });
  it('1st state transition', async () => {
    const w1 = await stateTransitionWitness(privateKey, authClaim, trees, [claim1, claim2, claim3], []);
    console.log(w1.isOldStateGenesis);
  });

  it('2nd state transition', async () => {
    await stateTransitionWitness(
      privateKey,
      authClaim,
      trees,
      [claim4],
      [claim1.getRevocationNonce(), claim2.getRevocationNonce()]
    );
  });
  let witness: StateTransitionWitness;
  it('3rd state transition', async () => {
    witness = await stateTransitionWitness(privateKey, authClaim, trees, [claim5], [claim3.getRevocationNonce()]);
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
      [claim5.getRevocationNonce()]
    );

    await circuitCheck(witness);
  }).timeout(100000);

  it.skip('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/witnesses/circom_test/bin/stateTransition.wasm',
      'src/witnesses/circom_test/bin/stateTransition.zkey'
    );
  }).timeout(100000);
});
