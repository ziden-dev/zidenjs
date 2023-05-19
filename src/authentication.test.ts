// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import { newClaim, withIndexData, schemaHashFromBigInt } from './claim/entry.js';
import { SMTLevelDb } from './db/level_db.js';
import { setupParams } from './global.js';
import { Auth, IdOwnershipBySignatureWitness } from './index.js';
import { State } from './state/state.js';
import { newAuthFromPrivateKey, signChallenge } from './state/auth.js';
import {
  idOwnershipBySignatureWitnessWithPrivateKey,
  idOwnershipBySignatureWitnessWithSignature,
} from './witnesses/authentication.js';
import { Gist } from './gist/gist.js';
import path from 'path';

describe('test authentication', async () => {
  let privateKey: Buffer;
  let auth: Auth;
  let state: State;
  let gist: Gist;
  let authsDb: SMTLevelDb;
  let claimsDb: SMTLevelDb;
  let claimRevDb: SMTLevelDb;
  let gistDb: SMTLevelDb;
  it('set up trees', async () => {
    await setupParams();
    privateKey = Buffer.alloc(32, 1);
    auth = newAuthFromPrivateKey(privateKey);

    authsDb = new SMTLevelDb('src/db_test/auths');
    claimsDb = new SMTLevelDb('src/db_test/claims');
    claimRevDb = new SMTLevelDb('src/db_test/claimRev');
    gistDb = new SMTLevelDb('src/db_test/gist');
    state = await State.generateState([auth], authsDb, claimsDb, claimRevDb);
    gist = await Gist.generateGist(gistDb);
  }).timeout(10000);

  let idOwnershipWitness: IdOwnershipBySignatureWitness;
  it('idOwnership with custom challenge', async () => {
    const challenge = BigInt('123456');
    const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861775'));
    const claim1 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)));
    const claim2 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 3), Buffer.alloc(30, 4)));
    const claim3 = newClaim(schemaHash, withIndexData(Buffer.alloc(30, 10), Buffer.alloc(30, 5)));
    await state.insertClaim(claim1);
    await state.insertClaim(claim2);
    await state.insertClaim(claim3);
    await state.revokeClaim(claim1.getRevocationNonce());
    await state.revokeClaim(claim2.getRevocationNonce());
    await state.revokeClaim(claim3.getRevocationNonce());
    const auth1 = newAuthFromPrivateKey(Buffer.alloc(32, 2));
    await state.insertAuth(auth1);
    
    await gist.insertGist(state.genesisID, state.getIdenState());

    idOwnershipWitness = await idOwnershipBySignatureWitnessWithPrivateKey(privateKey, auth, challenge, state, gist);
    
    const circuit = await wasm_tester(path.join('src', 'circom_test', 'idOwnershipBySignatureV2.circom'));
    const w0 = await circuit.calculateWitness(idOwnershipWitness, true);
    await circuit.checkConstraints(w0);
  }).timeout(20000);

  it('idOwnership with custom challenge and signature', async () => {
    const challenge = BigInt('1234565');
    const signature = await signChallenge(privateKey, challenge);
    idOwnershipWitness = await idOwnershipBySignatureWitnessWithSignature(signature, auth, state, gist);
    const circuit = await wasm_tester(path.join('src', 'circom_test', 'idOwnershipBySignatureV2.circom'));
    const w1 = await circuit.calculateWitness(idOwnershipWitness, true);
    await circuit.checkConstraints(w1);
  }).timeout(20000);
}).timeout(10000);
