import { newClaim, withIndexData, schemaHashFromBigInt, Entry } from '../claim/entry.js';
import { IDType } from '../claim/id.js';
import { Trees } from './trees.js';

// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { SMTLevelDb } from '../db/level_db.js';
import { expect } from 'chai';
import { getZidenParams, setupParams } from '../global.js';

describe('test trees', async () => {
  let trees: Trees;
  let claimsDb: SMTLevelDb;
  let authDb: SMTLevelDb;
  let authClaim1: Entry;
  let authClaim2: Entry;
  it('set up params', async () => {
    await setupParams();
  }).timeout(10000);
  it('generate new trees', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861770'));
    authClaim1 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 2)));
    authClaim2 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)));
    claimsDb = new SMTLevelDb('src/trees/db_test/claims');
    authDb = new SMTLevelDb('src/trees/db_test/auth');
  }).timeout(10000);
  it('benchmark generate trees', async () => {
    trees = await Trees.generateID([authClaim1, authClaim2], claimsDb, authDb, IDType.Default);
    console.log(authClaim1.getRevocationNonce());
    console.log(authClaim2.getRevocationNonce());
  });
  it('test getClaimHeader circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkIdenStateMatchesRoots.circom'));
    const idenState = trees.getIdenState();
    const w = await circuit.calculateWitness(
      {
        claimsTreeRoot: getZidenParams().F.toObject(trees.claimsTree.root),
        authTreeRoot: getZidenParams().F.toObject(trees.authTree.root),
        expectedState: idenState,
      },
      true
    );
    await circuit.checkConstraints(w);
  }).timeout(10000);

  it('test insert claim', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861771'));
    const claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 2)));
    await trees.insertClaim(claim);

    const claimExistProof = await trees.generateClaimExistsProof(claim.hiRaw());
    const witness = {
      ...claimExistProof,
      claim: claim.getDataForCircuit(),
    };
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkClaimExists.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(10000);

  it('test insert auth claim', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861770'));
    const authClaim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 5), Buffer.alloc(30, 2)));
    await trees.insertAuthClaim(authClaim);
    console.log(authClaim.getRevocationNonce());

    const claimExistProof = await trees.generateClaimExistsProof(authClaim.hiRaw(), false);
    const witness = {
      ...claimExistProof,
      claim: authClaim.getDataForCircuit(),
    };
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkAuthClaimExists.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(10000);

  it('test insert claims', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861771'));
    const claim1 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)));
    const claim2 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 3), Buffer.alloc(30, 4)));
    const claim3 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 4), Buffer.alloc(30, 5)));
    const claim4 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 20), Buffer.alloc(30, 30)));
    const claim5 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 30), Buffer.alloc(30, 40)));
    const claim6 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 40), Buffer.alloc(30, 50)));
    await trees.insertClaim(claim1);
    await trees.insertClaim(claim2);
    await trees.insertClaim(claim3);
    await trees.insertClaim(claim4);
    await trees.insertClaim(claim5);
    await trees.insertClaim(claim6);
  }).timeout(10000);

  it('test inserting a claim multiple times', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861772'));
    const claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 9)));
    for (let i = 0; i < 100; i++) {
      await trees.insertClaim(claim);
    }

    try {
      await trees.insertClaim(claim);
    } catch (err) {
      expect((err as Error).message).to.be.equal('Failed inserting caused by collision');
    }

    await trees.insertClaim(claim, 101);
  }).timeout(10000);
});
