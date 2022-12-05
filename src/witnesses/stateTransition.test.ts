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
  Entry,
  withSlotData,
} from '../claim/entry.js';
import { IDType } from '../claim/id.js';
import { SMTLevelDb } from '../db/level_db.js';
import { SMTType, Trees } from '../trees/trees.js';
import { StateTransitionWitness, stateTransitionWitness, stateTransitionWitnessWithHiHv } from './stateTransition.js';
import { setupParams } from '../global.js';
import { bitsToNum } from '../utils.js';

describe('test state transition with binary merkle tree', async () => {
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
    await setupParams();
    privateKey = Buffer.alloc(32, 1);

    authClaim = await newAuthClaimFromPrivateKey(privateKey);
    claimsDb = new SMTLevelDb('src/witnesses/db_test/state_db/claims');
    revocationDb = new SMTLevelDb('src/witnesses/db_test/state_db/revocation');
    rootsDb = new SMTLevelDb('src/witnesses/db_test/state_db/roots');

    trees = await Trees.generateID([authClaim], claimsDb, revocationDb, rootsDb, IDType.Default, 32, SMTType.BinSMT);

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
    const w1 = await stateTransitionWitness(privateKey, authClaim, trees, [claim1], []);
    await circuitCheck(w1)
    await stateTransitionWitness(privateKey, authClaim, trees, [claim2, claim3], []);
  }).timeout(20000);

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

  it('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/witnesses/circom_test/bin/stateTransition.wasm',
      'src/witnesses/circom_test/bin/stateTransition.zkey'
    );
  }).timeout(100000);

  it('test for contract', async () => {
    const issuerPk = Buffer.alloc(32, 1);

    const issuerAuthClaim = await newAuthClaimFromPrivateKey(privateKey);
    const issuerClaimsDb = new SMTLevelDb('src/witnesses/db_test/state_db/claims_contract');
    const issuerRevsDb = new SMTLevelDb('src/witnesses/db_test/state_db/revocation_contract');
    const issuerRootsDb = new SMTLevelDb('src/witnesses/db_test/state_db/roots_contract');

    const issuerTree = await Trees.generateID(
      [issuerAuthClaim],
      issuerClaimsDb,
      issuerRevsDb,
      issuerRootsDb,
      IDType.Default,
      32,
      SMTType.BinSMT
    );

    const issuerId = bitsToNum(issuerTree.userID);

    console.log('Issuer ID : ', issuerId);

    let schemaHash = schemaHashFromBigInt(BigInt('123456789'));

    let h1IndexA, h1IndexB, h1ValueA, h1ValueB;
    let h2IndexA, h2IndexB, h2ValueA, h2ValueB;
    h1IndexA = Buffer.alloc(32, 0);
    h1IndexA.write('Vitalik Buterin', 'utf-8');
    h1IndexB = Buffer.alloc(32, 0);
    h1IndexB.writeBigInt64LE(BigInt(19940131));
    h1ValueA = Buffer.alloc(32, 0);
    h1ValueA.writeBigInt64LE(BigInt(100));
    h1ValueB = Buffer.alloc(32, 0);
    h1ValueB.writeBigInt64LE(BigInt(120));

    h2IndexA = Buffer.alloc(32, 0);
    h2IndexA.write('Changpeng Zhao', 'utf-8');
    h2IndexB = Buffer.alloc(32, 0);
    h2IndexB.writeBigInt64LE(BigInt(19771009));
    h2ValueA = Buffer.alloc(32, 0);
    h2ValueA.writeBigInt64LE(BigInt(101));
    h2ValueB = Buffer.alloc(32, 0);
    h2ValueB.writeBigInt64LE(BigInt(111));

    const holder1Claim = newClaim(schemaHash, withIndexData(h1IndexA, h1IndexB), withValueData(h1ValueA, h1ValueB));

    const stateTransitionInput = await stateTransitionWitness(
      issuerPk,
      issuerAuthClaim,
      issuerTree,
      [holder1Claim],
      []
    );

    // const { proof, publicSignals } = await groth16.fullProve(
    //   stateTransitionInput,
    //   'src/witnesses/circom_test/bin/stateTransition.wasm',
    //   'src/witnesses/circom_test/bin/stateTransition.zkey'
    // );

    // console.log(proof);
    // console.log(publicSignals);
    await circuitCheck(stateTransitionInput);
  }).timeout(100000);
});
