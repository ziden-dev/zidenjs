// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import path from 'path';
import { Auth, Query, OPERATOR, QuerySigWitness } from './index.js';
import { Entry, newClaim, schemaHashFromBigInt, withIndexID, withSlotData } from './claim/entry.js';
import { SMTLevelDb } from './db/index.js';
import { setupParams } from './global.js';
import { newAuthFromPrivateKey, signChallenge } from './state/auth.js';
import { State } from './state/state.js';
import { numToBits, setBits } from './utils.js';
import {
  holderGenerateQuerySigWitnessWithPrivateKey,
  holderGenerateQuerySigWitnessWithSignature,
  kycGenerateNonRevQuerySigInput,
  kycGenerateQuerySigInput,
} from './witnesses/querySig.js';

describe('test query sig', async () => {
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

  let holderAuth: Auth;
  let issuerAuth: Auth;
  let holderPriv: Buffer;
  let issuerPriv: Buffer;

  let claim1: Entry;
  let claim2: Entry;

  let circuitCheck: (witness: QuerySigWitness) => Promise<void>;
  it('set up trees and claims', async () => {
    await setupParams();
    holderPriv = Buffer.alloc(32, 1);
    issuerPriv = Buffer.alloc(32, 2);

    holderAuth = newAuthFromPrivateKey(holderPriv);
    issuerAuth = newAuthFromPrivateKey(issuerPriv);

    authsDb = new SMTLevelDb('src/db_test/auths');
    claimsDb = new SMTLevelDb('src/db_test/claims');
    authRevDb = new SMTLevelDb('src/db_test/authRev');
    claimRevDb = new SMTLevelDb('src/db_test/claimRev');

    authsDb1 = new SMTLevelDb('src/db_test/auths1');
    claimsDb1 = new SMTLevelDb('src/db_test/claims1');
    authRevDb1 = new SMTLevelDb('src/db_test/authRev1');
    claimRevDb1 = new SMTLevelDb('src/db_test/claimRev1');

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

    circuitCheck = async (witness: QuerySigWitness) => {
      //return;
      const circuit = await wasm_tester(path.join('src', 'circom_test', 'credentialAtomicQuerySig.circom'));
      const w = await circuit.calculateWitness(witness, true);
      await circuit.checkConstraints(w);
    };
  }).timeout(10000);

  it('test query with PritaveKey', async () => {
    const kycQuerySigInput = await kycGenerateQuerySigInput(issuerPriv, issuerAuth, claim1, issuerState);
    const kycQueryNonRevQuerySigInput = await kycGenerateNonRevQuerySigInput(claim1.getRevocationNonce(), issuerState);
    const witness = await holderGenerateQuerySigWitnessWithPrivateKey(
      claim1,
      holderPriv,
      holderAuth,
      BigInt(1),
      holderState,
      kycQuerySigInput,
      kycQueryNonRevQuerySigInput,
      query1
    );
    await circuitCheck(witness);
  }).timeout(10000);

  it('test query with Signature', async () => {
    const kycQuerySigInput = await kycGenerateQuerySigInput(issuerPriv, issuerAuth, claim2, issuerState);
    const kycQueryNonRevQuerySigInput = await kycGenerateNonRevQuerySigInput(claim2.getRevocationNonce(), issuerState);
    const signature = await signChallenge(holderPriv, BigInt(1));
    const witness = await holderGenerateQuerySigWitnessWithSignature(
      claim2,
      signature,
      holderAuth,
      holderState,
      kycQuerySigInput,
      kycQueryNonRevQuerySigInput,
      query2
    );
    await circuitCheck(witness);
  }).timeout(10000);
});
