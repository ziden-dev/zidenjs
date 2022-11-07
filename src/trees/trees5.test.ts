import { newClaim, withIndexData, schemaHashFromBigInt, Entry } from '../claim/entry';
import { IDType } from '../claim/id';
import { Trees } from './trees';

// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { SMTLevelDb } from '../db/level_db';
import { buildHash0Hash1, buildHasher, buildSnarkField, Hash0, Hash1, Hasher, SnarkField } from '../global';
import { expect } from 'chai';

describe('test trees', async () => {
  let F: SnarkField;
  let trees: Trees;
  let claimsDb: SMTLevelDb;
  let revocationDb: SMTLevelDb;
  let rootsDb: SMTLevelDb;
  let authClaim1: Entry;
  let authClaim2: Entry;
  let hasher: Hasher;
  let hash0: Hash0;
  let hash1: Hash1;
  it('set up params', async () => {
    F = await buildSnarkField();
    hasher = await buildHasher();
    const hs = buildHash0Hash1(hasher, F);
    hash0 = hs.hash0;
    hash1 = hs.hash1;
  }).timeout(10000);
  it('generate new trees', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861770'));
    authClaim1 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 2)));
    authClaim2 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)));
    claimsDb = new SMTLevelDb('src/trees/db_test/claims5', F);
    revocationDb = new SMTLevelDb('src/trees/db_test/revocation5', F);
    rootsDb = new SMTLevelDb('src/trees/db_test/roots5', F);
  }).timeout(10000);
  it('benchmark generate trees', async () => {
    trees = await Trees.generateID(
      F,
      hash0,
      hash1,
      hasher,
      [authClaim1, authClaim2],
      claimsDb,
      revocationDb,
      rootsDb,
      IDType.Default
    );
  });
  it('test getClaimHeader circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkIdenStateMatchesRoots5.circom'));
    const idenState = trees.getIdenState();
    const w = await circuit.calculateWitness(
      {
        claimsTreeRoot: F.toObject(trees.claimsTree.root),
        revTreeRoot: F.toObject(trees.revocationTree.root),
        rootsTreeRoot: F.toObject(trees.rootsTree.root),
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

    const claimExistProof = await trees.generateClaimExistsProof(claim.hiRaw(hasher));
    const witness = {
      ...claimExistProof,
      claim: claim.getDataForCircuit(),
    };
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkClaimExists5.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(10000);

  it('prepare and insert batch claims with hi hv', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861771'));
    const claimHiHvs: Array<[ArrayLike<number>, ArrayLike<number>]> = [];
    for (let i = 0; i < 10; i++) {
      let claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 11 * i), Buffer.alloc(30, 11 * i)));
      claim = await trees.prepareClaimForInsert(claim, 10);
      claimHiHvs.push([claim.hiRaw(hasher), claim.hvRaw(hasher)]);
    }
    await trees.batchInsertClaimByHiHv(claimHiHvs);
  }).timeout(10000);

  it('should insert fail due to collision', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861771'));
    const claimHiHvs: Array<[ArrayLike<number>, ArrayLike<number>]> = [];
    try {
      for (let i = 0; i < 10; i++) {
        let claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 11 * i), Buffer.alloc(30, 11 * i)));
        claim = await trees.prepareClaimForInsert(claim, 1);
        claimHiHvs.push([claim.hiRaw(hasher), claim.hvRaw(hasher)]);
      }
    } catch (err) {
      expect((err as Error).message).to.be.equal(
        'Failed inserting caused by collision, please try increasing max attemp times'
      );
    }
  });
  it('test claim not revoked', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861771'));
    const claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 2)));
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
    await trees.revokeClaim(claim1.getRevocationNonce());
    await trees.revokeClaim(claim2.getRevocationNonce());
    await trees.revokeClaim(claim3.getRevocationNonce());
    await trees.revokeClaim(claim4.getRevocationNonce());
    await trees.revokeClaim(claim5.getRevocationNonce());
    await trees.revokeClaim(claim6.getRevocationNonce());

    const claimNonRev = claim.getRevocationNonce();
    const claimNonRevProof = await trees.generateClaimNotRevokedProof(claimNonRev);
    const witness = {
      ...claimNonRevProof,
      claim: claim.getDataForCircuit(),
    };
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkClaimNotRevoked5.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
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
