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
  withValueData,
  withIndexID,
  withExpirationDate,
  withFlagExpirable,
  Entry,
} from '../claim/entry.js';
import { SMTLevelDb } from '../db/level_db.js';
import { Trees } from '../trees/trees.js';
import { numToBits } from '../utils.js';
import {
  kycGenerateQuerySigInput,
  holderGenerateQuerySigWitness,
  KYCQuerySigInput,
  QuerySigWitness,
} from './querySig.js';

import { OPERATOR } from './query.js';
import { setupParams } from '../global.js';

describe('test query sig', async () => {
  let claimsDb: SMTLevelDb;
  let authDb: SMTLevelDb;
  let issuerPrivateKey: Buffer;
  let issuerAuthClaim: Entry;
  let issuerTrees: Trees;
  let holderPrivateKey: Buffer;
  let holderTrees: Trees;
  let holderAuthClaim: Entry;
  it('create trees for kyc service and holder', async () => {
    await setupParams();
    claimsDb = new SMTLevelDb('src/witnesses/db_test/query_sig/claims');
    authDb = new SMTLevelDb('src/witnesses/db_test/query_sig/auth');
    issuerPrivateKey = Buffer.alloc(32, 1);
    issuerAuthClaim = await newAuthClaimFromPrivateKey(issuerPrivateKey);
    issuerTrees = await Trees.generateID(
      [issuerAuthClaim],
      claimsDb,
      authDb
    );

    holderPrivateKey = Buffer.alloc(32, 2);
    holderAuthClaim = await newAuthClaimFromPrivateKey(holderPrivateKey);
    holderTrees = await Trees.generateID(
      [holderAuthClaim],
      new SMTLevelDb('src/witnesses/db_test/query_sig_holder/claims'),
      new SMTLevelDb('src/witnesses/db_test/query_sig_holder/auth')
    );
  }).timeout(10000);

  let issuerClaim: Entry;
  let kycQuerySigInput: KYCQuerySigInput;
  it('issuer issue issuerClaim for holder', async () => {
    const indexSlotA = BigInt(20010209);
    const indexSlotB = BigInt(1);
    const valueSlotA = BigInt(120);
    const valueSlotB = BigInt(300);
    const schemaHash = schemaHashFromBigInt(BigInt('12345'));
    issuerClaim = newClaim(
      schemaHash,
      withIndexData(numToBits(indexSlotA, 32), numToBits(indexSlotB, 32)),
      withValueData(numToBits(valueSlotA, 32), numToBits(valueSlotB, 32)),
      withExpirationDate(BigInt(Date.now() + 100000)),
      withFlagExpirable(true),
      withIndexID(holderTrees.userID)
    );

    kycQuerySigInput = await kycGenerateQuerySigInput(
      issuerPrivateKey,
      issuerAuthClaim,
      issuerClaim,
      issuerTrees
    );
    console.log('KYC Query Sig Input: ', kycQuerySigInput);
  }).timeout(10000);

  let witness: QuerySigWitness;
  it('holder query slot index A with operator LESS THAN', async () => {
    const challenge = BigInt('12345');
    witness = await holderGenerateQuerySigWitness(
      issuerClaim,
      holderPrivateKey,
      holderAuthClaim,
      challenge,
      holderTrees,
      kycQuerySigInput,
      2,
      OPERATOR.LESS_THAN,
      [BigInt(20010210)],
      10,
      0,
      100,
      Date.now()
    );
    console.log(witness);
  });
  it('test circuit constranit', async () => {
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'circom_test', 'bin', 'credentialAtomicQuerySig.circom')
    );
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(100000);
  it('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/witnesses/circom_test/bin/credentialAtomicQuerySig.wasm',
      'src/witnesses/circom_test/bin/credentialAtomicQuerySig.zkey'
    );
  }).timeout(100000);
});
