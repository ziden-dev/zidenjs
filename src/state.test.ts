import { newClaim, withIndexData, schemaHashFromBigInt } from './claim/entry.js';
import crypto from 'crypto';
// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { SMTLevelDb } from './db/level_db.js';
import { expect } from 'chai';
import { setupParams } from './global.js';
import { State } from './state/state.js';
import { Auth } from './index.js';
import { newAuthFromPrivateKey } from './state/auth.js';

describe('test state', async () => {
  let state: State;
  let authsDb: SMTLevelDb;
  let claimsDb: SMTLevelDb;
  let authRevDb: SMTLevelDb;
  let claimRevDb: SMTLevelDb;

  let priv1: Buffer;
  let priv2: Buffer;
  let priv3: Buffer;
  let auth1: Auth;
  let auth2: Auth;
  let auth3: Auth;
  it('set up params', async () => {
    await setupParams();
  }).timeout(10000);

  it('setup auths, dbs', async () => {
    authsDb = new SMTLevelDb('src/db_test/auths');
    claimsDb = new SMTLevelDb('src/db_test/claims');
    authRevDb = new SMTLevelDb('src/db_test/authRev');
    claimRevDb = new SMTLevelDb('src/db_test/claimRev');

    priv1 = crypto.randomBytes(32);
    priv2 = crypto.randomBytes(32);
    priv3 = crypto.randomBytes(32);

    auth1 = newAuthFromPrivateKey(priv1);
    auth2 = newAuthFromPrivateKey(priv2);
    auth3 = newAuthFromPrivateKey(priv3);
  }).timeout(10000);
  it('generate state', async () => {
    state = await State.generateState([auth1, auth2], authsDb, claimsDb, authRevDb, claimRevDb);
  });
  it('test root match circuit', async () => {
    const circuit = await wasm_tester(path.join('src', 'state', 'circom_test', 'checkIdenStateMatchesRoots.circom'));
    const rootsMatchProof = await state.generateRootsMatchProof();
    const w = await circuit.calculateWitness(rootsMatchProof, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  it('test insert claim', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861771'));
    const claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 2)));
    await state.insertClaim(claim);

    const claimExistsProof = await state.generateClaimExistsProof(claim.hiRaw());
    const witness = {
      ...claimExistsProof,
      claim: claim.getDataForCircuit(),
    };
    const circuit = await wasm_tester(path.join('src', 'state', 'circom_test', 'checkClaimExists.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  it('test claim not revoked', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861771'));
    const claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 2)));
    const claim1 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)));
    const claim2 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 3), Buffer.alloc(30, 4)));
    const claim3 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 4), Buffer.alloc(30, 5)));
    const claim4 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 20), Buffer.alloc(30, 30)));
    const claim5 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 30), Buffer.alloc(30, 40)));
    const claim6 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 40), Buffer.alloc(30, 50)));
    await state.insertClaim(claim1);
    await state.insertClaim(claim2);
    await state.insertClaim(claim3);
    await state.insertClaim(claim4);
    await state.insertClaim(claim5);
    await state.insertClaim(claim6);
    await state.revokeClaim(claim1.getRevocationNonce());
    await state.revokeClaim(claim2.getRevocationNonce());
    await state.revokeClaim(claim3.getRevocationNonce());
    await state.revokeClaim(claim4.getRevocationNonce());
    await state.revokeClaim(claim5.getRevocationNonce());
    await state.revokeClaim(claim6.getRevocationNonce());

    const claimNonRev = claim.getRevocationNonce();
    const claimNonRevProof = await state.generateClaimNotRevokedProof(claimNonRev);
    const witness = {
      ...claimNonRevProof,
      claim: claim.getDataForCircuit(),
    };

    console.log(claimNonRevProof);
    const circuit = await wasm_tester(path.join('src', 'state', 'circom_test', 'checkClaimNotRevoked.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  it('test inserting a claim multiple times', async () => {
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861772'));
    const claim = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 1), Buffer.alloc(30, 9)));
    for (let i = 0; i < 100; i++) {
      await state.insertClaim(claim);
    }

    try {
      await state.insertClaim(claim);
    } catch (err) {
      expect((err as Error).message).to.be.equal('Failed inserting caused by collision');
    }

    await state.insertClaim(claim, 101);
  }).timeout(20000);

  it('test insert auth', async () => {
    await state.insertAuth(auth3);
    const authExistsProof = await state.generateAuthExistsProof(auth3.authHi);
    const witness = {
      ...authExistsProof,
      authPubX: auth3.pubKey.X,
      authPubY: auth3.pubKey.Y,
      authHi: auth3.authHi,
    };

    const circuit = await wasm_tester(path.join('src', 'state', 'circom_test', 'checkAuthExists.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);

  it('test auth not revoked', async () => {
    const authNotRevokedProof = await state.generateAuthNotRevokedProof(auth1.authHi);

    const witness = {
      ...authNotRevokedProof,
    };

    console.log(witness);

    const circuit = await wasm_tester(path.join('src', 'state', 'circom_test', 'checkAuthNotRevoked.circom'));
    const w = await circuit.calculateWitness(witness, true);
    await circuit.checkConstraints(w);
  }).timeout(20000);
});
