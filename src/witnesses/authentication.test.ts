// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import path from 'path';

import { newAuthClaimFromPrivateKey } from '../claim/auth-claim.js';
import { newClaim, withIndexData, schemaHashFromBigInt, Entry } from '../claim/entry.js';
import { IDType } from '../claim/id.js';
import { SMTType, Trees } from '../trees/trees.js';
import {
  AuthenticationWitness,
  authenticationWitness,
  IdOwnershipBySignatureWitness,
  idOwnershipBySignatureWitness,
} from './authentication.js';
import { SMTLevelDb } from '../db/level_db.js';
import { setupParams } from '../global.js';

describe('test authentication', async () => {
  let privateKey: Buffer;
  let authClaim: Entry;
  let authTrees: Trees;

  it('set up trees', async () => {
    await setupParams();
    privateKey = Buffer.alloc(32, 1);
    authClaim = await newAuthClaimFromPrivateKey(privateKey);

    const claimsDb = new SMTLevelDb('src/witnesses/db_test/auth/claims');
    const revocationDb = new SMTLevelDb('src/witnesses/db_test/auth/revocation');
    const rootsDb = new SMTLevelDb('src/witnesses/db_test/auth/roots');
    authTrees = await Trees.generateID(
      [authClaim],
      claimsDb,
      revocationDb,
      rootsDb,
      IDType.Default,
      32,
      SMTType.BinSMT
    );
  }).timeout(10000);

  let authWitness: AuthenticationWitness;
  it('authenticate with custom challenge', async () => {
    const challenge = BigInt('123456');
    authWitness = await authenticationWitness(privateKey, authClaim, challenge, authTrees);
    const circuit = await wasm_tester(path.join('src', 'witnesses', 'circom_test', 'bin', 'authentication.circom'));
    const w = await circuit.calculateWitness(authWitness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  let idOwnershipWitness: IdOwnershipBySignatureWitness;
  it('idOwnership with custom challenge', async () => {
    const challenge = BigInt('123456');
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861775'));
    const claim1 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)));
    const claim2 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 3), Buffer.alloc(30, 4)));
    const claim3 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 10), Buffer.alloc(30, 5)));
    await authTrees.insertClaim(claim1);
    await authTrees.insertClaim(claim2);
    await authTrees.insertClaim(claim3);
    await authTrees.revokeClaim(claim1.getRevocationNonce());
    await authTrees.revokeClaim(claim2.getRevocationNonce());
    await authTrees.revokeClaim(claim3.getRevocationNonce());

    const authClaim1 = await newAuthClaimFromPrivateKey(Buffer.alloc(32, 2));

    await authTrees.insertClaim(authClaim1);

    idOwnershipWitness = await idOwnershipBySignatureWitness(privateKey, authClaim, challenge, authTrees);
    const circuit = await wasm_tester(
      path.join('src', 'witnesses', 'circom_test', 'bin', 'idOwnershipBySignature.circom')
    );
    const w = await circuit.calculateWitness(idOwnershipWitness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  it.skip('benchmark proving time for id ownership by signature', async () => {
    await groth16.fullProve(
      idOwnershipWitness,
      'src/witnesses/circom_test/bin/idOwnershipBySignature.wasm',
      'src/witnesses/circom_test/bin/idOwnershipBySignature.zkey'
    );
  }).timeout(100000);
}).timeout(10000);
