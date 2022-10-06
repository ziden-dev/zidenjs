import { newClaim, withIndexData, schemaHashFromBigInt, Entry } from '../claim/entry.js';
import { IDType } from '../claim/id.js';
import { Trees } from './trees.js';

// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { SMTLevelDb } from '../db/level_db.js';
import { buildHash0Hash1, buildHasher, buildSnarkField, Hash0, Hash1, Hasher, SnarkField } from '../global.js';

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
    claimsDb = new SMTLevelDb('trees/db_test/claims', F);
    revocationDb = new SMTLevelDb('trees/db_test/revocation', F);
    rootsDb = new SMTLevelDb('trees/db_test/roots', F);
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
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkIdenStateMatchesRoots.circom'));
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
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkClaimExists.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(10000);

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
    const circuit = await wasm_tester(path.join('src', 'trees', 'circom_test', 'checkClaimNotRevoked.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(10000);
});
