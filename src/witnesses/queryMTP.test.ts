// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';

// @ts-ignore
import { groth16 } from 'snarkjs';

import path from 'path';
import { newAuthClaimFromPrivateKey, signChallenge } from '../claim/auth-claim.js';
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
import { IDType } from '../claim/id.js';
import { SMTLevelDb } from '../db/level_db.js';
import { SMTType, Trees } from '../trees/trees.js';
import { numToBits } from '../utils.js';
import {
  kycGenerateQueryMTPInput,
  holderGenerateQueryMTPWitness,
  kycGenerateNonRevQueryMTPInput,
  KYCQueryMTPInput,
  KYCNonRevQueryMTPInput,
  QueryMTPWitness,
  holderGenerateQueryMTPWitnessWithSignature,
} from './queryMTP.js';
import { OPERATOR } from './query.js';
import { setupParams } from '../global.js';

describe('test query atomic MTP', async () => {
  let claimsDb: SMTLevelDb;
  let revocationDb: SMTLevelDb;
  let rootsDb: SMTLevelDb;
  let issuerPrivateKey: Buffer;
  let issuerTrees: Trees;
  let holderPrivateKey: Buffer;
  let holderTrees: Trees;
  let holderAuthClaim: Entry;

  it('setup params', async () => {
    await setupParams();
    claimsDb = new SMTLevelDb('src/witnesses/db_test/query_mtp/claims');
    revocationDb = new SMTLevelDb('src/witnesses/db_test/query_mtp/revocation');
    rootsDb = new SMTLevelDb('src/witnesses/db_test/query_mtp/roots');
  }).timeout(10000);
  it('setup kyc auth claim', async () => {
    issuerPrivateKey = Buffer.alloc(32, 1);
    const issuerAuthClaim = await newAuthClaimFromPrivateKey(issuerPrivateKey);
    issuerTrees = await Trees.generateID(
      [issuerAuthClaim],
      claimsDb,
      revocationDb,
      rootsDb,
      IDType.Default,
      32,
      SMTType.BinSMT
    );
  }).timeout(10000);

  it('setup holder ID', async () => {
    holderPrivateKey = Buffer.alloc(32, 2);
    holderAuthClaim = await newAuthClaimFromPrivateKey(holderPrivateKey);
    const claimsDb = new SMTLevelDb('src/witnesses/db_test/query_mtp_holder/claims');
    const revocationDb = new SMTLevelDb('src/witnesses/db_test/query_mtp_holder/revocation');
    const rootsDb = new SMTLevelDb('src/witnesses/db_test/query_mtp_holder/roots');
    holderTrees = await Trees.generateID(
      [holderAuthClaim],
      claimsDb,
      revocationDb,
      rootsDb,
      IDType.Default,
      32,
      SMTType.BinSMT
    );
  }).timeout(10000);

  let issuerClaim: Entry;
  let kycQueryMTPInput: KYCQueryMTPInput;
  let kycQueryNonRevMTPInput: KYCNonRevQueryMTPInput;
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
    await issuerTrees.insertClaim(issuerClaim);
    kycQueryMTPInput = await kycGenerateQueryMTPInput(issuerClaim.hiRaw(), issuerTrees);
    kycQueryNonRevMTPInput = await kycGenerateNonRevQueryMTPInput(issuerClaim.getRevocationNonce(), issuerTrees);
  }).timeout(10000);

  let witness: QueryMTPWitness;
  let values: Array<BigInt>;
  let challenge: BigInt;
  it('setup for gen query MTP witness', async () => {
    values = [BigInt(20010210)];
    challenge = BigInt('12345');
  });
  it('Benchmark sign signature', async () => {
    await signChallenge(holderPrivateKey, challenge);
  });
  it('Benchmark holder auth claim MTP', async () => {
    await holderTrees.generateProofForClaim(
      holderAuthClaim.hiRaw(),
      holderAuthClaim.getRevocationNonce()
    );
  });
  it('holder query slot index A with OPERATOR LESS THAN', async () => {
    witness = await holderGenerateQueryMTPWitness(
      issuerClaim,
      holderPrivateKey,
      holderAuthClaim,
      challenge,
      holderTrees,
      kycQueryMTPInput,
      kycQueryNonRevMTPInput,
      2,
      OPERATOR.LESS_THAN,
      values,
      10,
      0,
      100,
    );
    console.log(witness);
  });

  it('test circuit constraints', async () => {
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'circom_test', 'bin', 'credentialAtomicQueryMTP.circom')
    );
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  it('holder query slot value B with OPERATOR EQUAL', async () => {
    values = [BigInt(300)];
    witness = await holderGenerateQueryMTPWitness(
      issuerClaim,
      holderPrivateKey,
      holderAuthClaim,
      challenge,
      holderTrees,
      kycQueryMTPInput,
      kycQueryNonRevMTPInput,
      7,
      OPERATOR.EQUAL,
      values,
      10,
      0,
      100
    );
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'circom_test', 'bin', 'credentialAtomicQueryMTP.circom')
    );
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(100000);

  it('holder query slot value B with OPERATOR EQUAL with signature', async () => {
    values = [BigInt(300)];
    const signature = await signChallenge(holderPrivateKey, challenge);
    witness = await holderGenerateQueryMTPWitnessWithSignature(
      issuerClaim,
      holderAuthClaim,
      signature,
      holderTrees,
      kycQueryMTPInput,
      kycQueryNonRevMTPInput,
      7,
      OPERATOR.EQUAL,
      values,
      10,
      0,
      100
    );
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'circom_test', 'bin', 'credentialAtomicQueryMTP.circom')
    );
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(100000);

  it.skip('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/witnesses/circom_test/bin/credentialAtomicQueryMTP.wasm',
      'src/witnesses/circom_test/bin/credentialAtomicQueryMTP.zkey'
    );
  }).timeout(100000);
});
