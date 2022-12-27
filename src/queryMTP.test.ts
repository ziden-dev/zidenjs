// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import path from 'path';
import { Entry, newClaim, schemaHashFromBigInt, withSlotData, withIndexID } from './claim/entry.js';
import { Auth, OPERATOR, Query, QueryMTPWitness } from './index.js';
import { State } from './state/state.js';
import { SMTLevelDb } from './db/index.js';
import { setupParams } from './global.js';
import { newAuthFromPrivateKey, signChallenge } from './state/auth.js';
import { numToBits, setBits } from './utils.js';
import {
  holderGenerateQueryMTPWitnessWithPrivateKey,
  holderGenerateQueryMTPWitnessWithSignature,
  kycGenerateNonRevQueryMTPInput,
  kycGenerateQueryMTPInput,
} from './witnesses/queryMTP.js';

describe('test credential query MTP', async () => {
  let holderPriv: Buffer;
  let issuerPriv: Buffer;
  let holderAuth: Auth;
  let issuerAuth: Auth;

  let claim1: Entry;
  let claim2: Entry;

  let holderState: State;
  let issuerState: State;

  let authsDb: SMTLevelDb;
  let claimsDb: SMTLevelDb;
  let authRevDb: SMTLevelDb;
  let claimRevDb: SMTLevelDb;

  let authsDb1: SMTLevelDb;
  let claimsDb1: SMTLevelDb;
  let authRevDb1: SMTLevelDb;
  let claimRevDb1: SMTLevelDb;

  let query1: Query;
  let query2: Query;

  let circuitCheck: (witness: QueryMTPWitness) => Promise<void>;
  it('set up trees and claims', async () => {
    await setupParams();
    holderPriv = Buffer.alloc(32, 1);
    issuerPriv = Buffer.alloc(32, 2);

    holderAuth = newAuthFromPrivateKey(holderPriv);
    issuerAuth = newAuthFromPrivateKey(issuerPriv);

    authsDb = new SMTLevelDb('src/db_test/auths');
    claimsDb = new SMTLevelDb('src/db_test/claims');
    authRevDb = new SMTLevelDb('src/db_test/authRev');
    claimRevDb = new SMTLevelDb('src/trees/claimRev');

    authsDb1 = new SMTLevelDb('src/db_test/auths1');
    claimsDb1 = new SMTLevelDb('src/db_test/claims1');
    authRevDb1 = new SMTLevelDb('src/db_test/authRev1');
    claimRevDb1 = new SMTLevelDb('src/trees/claimRev1');

    holderState = await State.generateState([holderAuth], authsDb, claimsDb, authRevDb, claimRevDb);
    issuerState = await State.generateState([issuerAuth], authsDb1, claimsDb1, authRevDb1, claimRevDb1);

    query1 = {
      slotIndex: 2,
      operator: OPERATOR.LESS_THAN,
      values: [BigInt(20040101)],
      valueTreeDepth: 6,
      from: 10,
      to: 100,
      timestamp: Date.now(),
      claimSchema: BigInt(12394),
    };

    query2 = {
      slotIndex: 6,
      operator: OPERATOR.IN,
      values: [BigInt(100), BigInt(101), BigInt(102), BigInt(103), BigInt(104)],
      valueTreeDepth: 6,
      from: 160,
      to: 170,
      timestamp: Date.now(),
      claimSchema: BigInt(1239466),
    };

    const slot1 = setBits(BigInt(0), query1.from, BigInt(20010101));
    const slot2 = setBits(BigInt(0), query2.from, BigInt(102));

    claim1 = newClaim(
      schemaHashFromBigInt(query1.claimSchema),
      withSlotData(query1.slotIndex, numToBits(slot1, 32)),
      withIndexID(holderState.userID)
    );

    claim2 = newClaim(
      schemaHashFromBigInt(query2.claimSchema),
      withSlotData(query2.slotIndex, numToBits(slot2, 32)),
      withIndexID(holderState.userID)
    );

    await issuerState.insertClaim(claim1);
    await issuerState.insertClaim(claim2);
    circuitCheck = async (witness: QueryMTPWitness) => {
      const circuit = await wasm_tester(path.join('src', 'circom_test', 'credentialAtomicQueryMTP.circom'));
      const w = await circuit.calculateWitness(witness, true);
      await circuit.checkConstraints(w);
    };
  }).timeout(100000);
  let witness: QueryMTPWitness;
  it.skip('test query 1', async () => {
    const kycQueryMTPInput = await kycGenerateQueryMTPInput(claim1.hiRaw(), issuerState);
    const kycNonRevQueryMTPInput = await kycGenerateNonRevQueryMTPInput(claim1.getRevocationNonce(), issuerState);
    witness = await holderGenerateQueryMTPWitnessWithPrivateKey(
      claim1,
      holderPriv,
      holderAuth,
      BigInt(1),
      holderState,
      kycQueryMTPInput,
      kycNonRevQueryMTPInput,
      query1
    );
    await circuitCheck(witness);
  }).timeout(100000);
  it('test query 2', async () => {
    const kycQueryMTPInput = await kycGenerateQueryMTPInput(claim2.hiRaw(), issuerState);
    const kycNonRevQueryMTPInput = await kycGenerateNonRevQueryMTPInput(claim2.getRevocationNonce(), issuerState);
    const signature = await signChallenge(holderPriv, BigInt(1));
    witness = await holderGenerateQueryMTPWitnessWithSignature(
      claim2,
      signature,
      holderAuth,
      holderState,
      kycQueryMTPInput,
      kycNonRevQueryMTPInput,
      query2
    );

    // await circuitCheck(witness)
  }).timeout(100000);
  it('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/circom_test/credentialAtomicQueryMTP.wasm',
      'src/circom_test/credentialAtomicQueryMTP.zkey'
    );
  }).timeout(100000);
});
