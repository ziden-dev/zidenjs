// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import path from 'path';
import {
  buildHash0Hash1,
  buildHasher,
  buildSigner,
  buildSnarkField,
  EDDSA,
  Hash0,
  Hash1,
  Hasher,
  SnarkField,
} from '../global.js';
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
import { Trees } from '../trees/trees.js';
import { StateTransitionWitness, stateTransitionWitness } from './stateTransition.js';

describe('test authentication', async () => {
  let F: SnarkField;
  let eddsa: EDDSA;
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
  let hasher: Hasher;
  let hash0: Hash0;
  let hash1: Hash1;
  it('set up trees and claims', async () => {
    F = await buildSnarkField();
    hasher = await buildHasher();
    const hs = buildHash0Hash1(hasher, F);
    hash0 = hs.hash0;
    hash1 = hs.hash1;
    eddsa = await buildSigner();
    privateKey = Buffer.alloc(32, 1);

    authClaim = await newAuthClaimFromPrivateKey(eddsa, F, privateKey);
    claimsDb = new SMTLevelDb('src/witnesses/db_test/state_db/claims', F);
    revocationDb = new SMTLevelDb('src/witnesses/db_test/state_db/revocation', F);
    rootsDb = new SMTLevelDb('src/witnesses/db_test/state_db/roots', F);

    trees = await Trees.generateID(
      F,
      hash0,
      hash1,
      hasher,
      [authClaim],
      claimsDb,
      revocationDb,
      rootsDb,
      IDType.Default
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
  }).timeout(10000);
  it('benchmark create claim', async () => {
    await newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 5), Buffer.alloc(30, 6)),
      withValueData(Buffer.alloc(30, 5), Buffer.alloc(30, 6)),
      withRevocationNonce(BigInt(100)),
      withVersion(BigInt(100)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
  });
  it('1st state transition', async () => {
    const w1 = await stateTransitionWitness(eddsa, privateKey, authClaim, trees, [claim1, claim2, claim3], [], hasher);
    console.log(w1.isOldStateGenesis);
  });

  it('2nd state transition', async () => {
    await stateTransitionWitness(
      eddsa,
      privateKey,
      authClaim,
      trees,
      [claim4],
      [claim1.getRevocationNonce(), claim2.getRevocationNonce()],
      hasher
    );
  });
  let witness: StateTransitionWitness;
  it('3rd state transition', async () => {
    witness = await stateTransitionWitness(
      eddsa,
      privateKey,
      authClaim,
      trees,
      [claim5],
      [claim3.getRevocationNonce()],
      hasher
    );
    console.log(witness.isOldStateGenesis);
  });

  it('test circuit constraint', async () => {
    const circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'stateTransition.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  it('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/witnesses/circom_test/stateTransition.wasm',
      'src/witnesses/circom_test/stateTransition.zkey'
    );
  }).timeout(100000);;
});
