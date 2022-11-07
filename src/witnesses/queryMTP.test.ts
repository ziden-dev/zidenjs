// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { SMTMemDb } from 'circomlibjs';

// @ts-ignore
import { groth16 } from 'snarkjs';

import path from 'path';
import {
  buildFMTHashFunction,
  buildHash0Hash1,
  buildHasher,
  buildSigner,
  buildSnarkField,
  EDDSA,
  Hash0,
  Hash1,
  Hasher,
  SnarkField,
} from '../global';
import { newAuthClaimFromPrivateKey, signChallenge } from '../claim/auth-claim';
import {
  newClaim,
  schemaHashFromBigInt,
  withIndexData,
  withValueData,
  withIndexID,
  withExpirationDate,
  withFlagExpirable,
  Entry,
} from '../claim/entry';
import { IDType } from '../claim/id';
import { SMTLevelDb } from '../db/level_db';
import { SMTType, Trees } from '../trees/trees';
import { numToBits } from '../utils';
import {
  kycGenerateQueryMTPInput,
  holderGenerateQueryMTPWitness,
  kycGenerateNonRevQueryMTPInput,
  KYCQueryMTPInput,
  KYCNonRevQueryMTPInput,
  QueryMTPWitness,
} from './queryMTP';
import { HashFunction } from './fixed-merkle-tree/index';
import { OPERATOR } from './query';

describe('test query atomic MTP', async () => {
  let F: SnarkField;
  let claimsDb: SMTLevelDb;
  let revocationDb: SMTLevelDb;
  let rootsDb: SMTLevelDb;
  let issuerPrivateKey: Buffer;
  let issuerTrees: Trees;
  let holderPrivateKey: Buffer;
  let holderTrees: Trees;
  let holderAuthClaim: Entry;
  let hash0: Hash0;
  let hash1: Hash1;
  let hasher: Hasher;
  let eddsa: EDDSA;
  let hashFunction: HashFunction;

  it('setup params', async () => {
    F = await buildSnarkField();
    claimsDb = new SMTLevelDb('src/witnesses/db_test/query_mtp/claims', F);
    revocationDb = new SMTLevelDb('src/witnesses/db_test/query_mtp/revocation', F);
    rootsDb = new SMTLevelDb('src/witnesses/db_test/query_mtp/roots', F);
    hasher = await buildHasher();
    const hs = buildHash0Hash1(hasher, F);
    hash0 = hs.hash0;
    hash1 = hs.hash1;
    eddsa = await buildSigner();
    hashFunction = buildFMTHashFunction(hash0, F);
  }).timeout(10000);
  it('setup kyc auth claim', async () => {
    issuerPrivateKey = Buffer.alloc(32, 1);
    const issuerAuthClaim = await newAuthClaimFromPrivateKey(eddsa, F, issuerPrivateKey);
    issuerTrees = await Trees.generateID(
      F,
      hash0,
      hash1,
      hasher,
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
    holderAuthClaim = await newAuthClaimFromPrivateKey(eddsa, F, holderPrivateKey);
    const claimsDb = new SMTMemDb(F);
    const revocationDb = new SMTMemDb(F);
    const rootsDb = new SMTMemDb(F);
    holderTrees = await Trees.generateID(
      F,
      hash0,
      hash1,
      hasher,
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
    kycQueryMTPInput = await kycGenerateQueryMTPInput(issuerClaim.hiRaw(issuerTrees.hasher), issuerTrees);
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
    await signChallenge(eddsa, F, holderPrivateKey, challenge);
  });
  it('Benchmark holder auth claim MTP', async () => {
    await holderTrees.generateProofForClaim(
      holderAuthClaim.hiRaw(holderTrees.hasher),
      holderAuthClaim.getRevocationNonce()
    );
  });
  it('holder query slot index A with OPERATOR LESS THAN', async () => {
    witness = await holderGenerateQueryMTPWitness(
      issuerClaim,
      eddsa,
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
      hashFunction,
      F
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
      eddsa,
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
      100,
      hashFunction,
      F
    );
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'circom_test', 'bin', 'credentialAtomicQueryMTP.circom')
    );
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(100000);

  it('benchmark proving time', async () => {
    await groth16.fullProve(
      witness,
      'src/witnesses/circom_test/bin/credentialAtomicQueryMTP.wasm',
      'src/witnesses/circom_test/bin/credentialAtomicQueryMTP.zkey'
    );
  }).timeout(100000);
});
