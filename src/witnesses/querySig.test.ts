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
} from '../global.js';
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
import { IDType } from '../claim/id.js';
import { SMTLevelDb } from '../db/level_db.js';
import { SMTType, Trees } from '../trees/trees.js';
import { numToBits } from '../utils.js';
import {
  kycGenerateQuerySigInput,
  kycGenerateQuerySigNonRevInput,
  holderGenerateQuerySigWitness,
  KYCQuerySigInput,
  KYCQuerySigNonRevInput,
  QuerySigWitness,
} from './querySig.js';
import { HashFunction } from './fixed-merkle-tree/index.js';
import { OPERATOR } from './query.js';

describe('test query sig', async () => {
  let F: SnarkField;
  let hash0: Hash0;
  let hash1: Hash1;
  let hasher: Hasher;
  let eddsa: EDDSA;
  let claimsDb: SMTLevelDb;
  let revocationDb: SMTLevelDb;
  let rootsDb: SMTLevelDb;
  let issuerPrivateKey: Buffer;
  let issuerAuthClaim: Entry;
  let issuerTrees: Trees;
  let holderPrivateKey: Buffer;
  let holderTrees: Trees;
  let holderAuthClaim: Entry;
  let hashFunction: HashFunction;
  it('create trees for kyc service and holder', async () => {
    F = await buildSnarkField();
    claimsDb = new SMTLevelDb('src/witnesses/db_test/query_sig/claims', F);
    revocationDb = new SMTLevelDb('src/witnesses/db_test/query_sig/revocation', F);
    rootsDb = new SMTLevelDb('src/witnesses/db_test/query_sig/roots', F);
    hasher = await buildHasher();
    const hs = buildHash0Hash1(hasher, F);
    hash0 = hs.hash0;
    hash1 = hs.hash1;
    hashFunction = buildFMTHashFunction(hash0, F);
    eddsa = await buildSigner();
    issuerPrivateKey = Buffer.alloc(32, 1);
    issuerAuthClaim = await newAuthClaimFromPrivateKey(eddsa, F, issuerPrivateKey);
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

    holderPrivateKey = Buffer.alloc(32, 2);
    holderAuthClaim = await newAuthClaimFromPrivateKey(eddsa, F, holderPrivateKey);
    holderTrees = await Trees.generateID(
      F,
      hash0,
      hash1,
      hasher,
      [holderAuthClaim],
      new SMTMemDb(F),
      new SMTMemDb(F),
      new SMTMemDb(F),
      IDType.Default,
      32,
      SMTType.BinSMT
    );
  }).timeout(10000);

  let issuerClaim: Entry;
  let kycQuerySigInput: KYCQuerySigInput;
  let kycQuerySigNonRevInput: KYCQuerySigNonRevInput;
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
      eddsa,
      hasher,
      issuerPrivateKey,
      issuerAuthClaim,
      issuerClaim,
      issuerTrees
    );
    console.log('KYC Query Sig Input: ', kycQuerySigInput);

    kycQuerySigNonRevInput = await kycGenerateQuerySigNonRevInput(issuerClaim.getRevocationNonce(), issuerTrees);

    console.log('KYC Query Sig NonRev Input: ', kycQuerySigNonRevInput);
  }).timeout(10000);

  let witness: QuerySigWitness;
  it('holder query slot index A with operator LESS THAN', async () => {
    const challenge = BigInt('12345');
    witness = await holderGenerateQuerySigWitness(
      issuerClaim,
      eddsa,
      holderPrivateKey,
      holderAuthClaim,
      challenge,
      holderTrees,
      kycQuerySigInput,
      kycQuerySigNonRevInput,
      2,
      OPERATOR.LESS_THAN,
      [BigInt(20010210)],
      10,
      0,
      100,
      hashFunction,
      F
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
