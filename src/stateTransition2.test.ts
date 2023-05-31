// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';

import {
  Entry,
  newClaim,
  withIndexID,
  schemaHashFromBigInt,
  withIndexData,
  withValueData,
} from './claim/entry.js';
import { Auth, StateTransitionWitness } from './index.js';
import { setupParams } from './global.js';
import { State } from './state/state.js';
import { SMTLevelDb } from './db/level_db.js';
import { newAuthFromPrivateKey } from './state/auth.js';
import crypto from 'crypto';
import { stateTransitionWitnessWithPrivateKey } from './witnesses/stateTransition.js';
import { Gist } from './gist/gist.js';

import path from 'path';

describe('test state transition', async () => {

  let priv1: Buffer;
  let priv2: Buffer;

  let auth1: Auth;
  let auth2: Auth;

  let claim1: Entry;

  let state1: State;
  let state2: State;

  let authsDb1: SMTLevelDb;
  let claimsDb1: SMTLevelDb;
  let claimRevDb1: SMTLevelDb;

  let authsDb2: SMTLevelDb;
  let claimsDb2: SMTLevelDb;
  let claimRevDb2: SMTLevelDb;

  let gist: Gist;
  let gistDb: SMTLevelDb;

  let circuitCheck: (witness: StateTransitionWitness) => Promise<void>;

  it('set up trees and claims', async () => {
    await setupParams();
    gistDb = new SMTLevelDb('db_test/gist');
    gist = await Gist.generateGist(gistDb);

      priv1 = crypto.randomBytes(32);
      auth1 = newAuthFromPrivateKey(priv1);
      authsDb1 = new SMTLevelDb('db_test/user1/auths');
      claimsDb1 = new SMTLevelDb('db_test/user1/claims');
      claimRevDb1 = new SMTLevelDb('db_test/user1/claimRev');
      state1 = await State.generateState([auth1], authsDb1, claimsDb1, claimRevDb1);


      priv2 = crypto.randomBytes(32);
      auth2 = newAuthFromPrivateKey(priv2);
      authsDb2 = new SMTLevelDb('db_test/user2/auths');
      claimsDb2 = new SMTLevelDb('db_test/user2/claims');
      claimRevDb2 = new SMTLevelDb('db_test/user2/claimRev');
      state2 = await State.generateState([auth2], authsDb2, claimsDb2, claimRevDb2);
      circuitCheck = async (witness: StateTransitionWitness) => {
        const circuit = await wasm_tester(path.join('src', 'circom_test', 'stateTransition.circom'));
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
      };
    }).timeout(30000);;

  it("user 0 add a new auth and new claim", async () => {

    const newPrivateKey = crypto.randomBytes(32);
    const newAuth = newAuthFromPrivateKey(newPrivateKey);
  
    const schemaHash = schemaHashFromBigInt(BigInt("42136162"));

    claim1 = newClaim(
      schemaHash,
      withIndexData(Buffer.alloc(30, 1234), Buffer.alloc(30, 7347)),
      withValueData(Buffer.alloc(30, 432987492), Buffer.alloc(30, 4342))
    );
    await setupParams();
    const inputs = await stateTransitionWitnessWithPrivateKey(
        priv1,
        auth1,
        state1,
        gist,
        [newAuth],
        [claim1],
        [],
        []
      );
      await circuitCheck(inputs);
    await gist.insertGist(state1.genesisID,state1.getIdenState());
    
  }).timeout(30000);

  it("user 0 rev new claim", async () => {
    await setupParams();
    const inputs = await stateTransitionWitnessWithPrivateKey(
        priv1,
        auth1,
        state1,
        gist,
        [],
        [],
        [claim1.getRevocationNonce()],
        []
      );
      await circuitCheck(inputs);

    await gist.insertGist(state1.genesisID,state1.getIdenState());
  }).timeout(30000);

  it("user 1 add a new auth and new claim", async () => {

    const newPrivateKey = crypto.randomBytes(32);
    const newAuth = newAuthFromPrivateKey(newPrivateKey);
    const schemaHash = schemaHashFromBigInt(BigInt("42136162"));
    const claim = newClaim(
      schemaHash,
      withIndexID(state2.userID),
      withIndexData(Buffer.alloc(30, 1234), Buffer.alloc(30, 7347)),
      withValueData(Buffer.alloc(30, 432987492), Buffer.alloc(30, 4342))
    );
    await setupParams();
    const inputs = await stateTransitionWitnessWithPrivateKey(
        priv2,
        auth2,
        state2,
        gist,
        [newAuth],
        [claim],
        [],
        []
      );
    await gist.insertGist(
      state2.genesisID,
      state2.getIdenState()
    );
    await circuitCheck(inputs);
    console.log(" Gist Root now = ", gist.getRoot())
  }).timeout(30000);;

  it("user 1 add a new auth and new claim seconcd", async () => {

    const newPrivateKey = crypto.randomBytes(32);
    const newAuth = newAuthFromPrivateKey(newPrivateKey);
    const schemaHash = schemaHashFromBigInt(BigInt("42136162"));
    const claim = newClaim(
      schemaHash,
      withIndexID(state2.userID),
      withIndexData(Buffer.alloc(30, 1234), Buffer.alloc(30, 7347)),
      withValueData(Buffer.alloc(30, 432987492), Buffer.alloc(30, 4342))
    );
    await setupParams();
    const inputs = await stateTransitionWitnessWithPrivateKey(
        priv2,
        auth2,
        state2,
        gist,
        [newAuth],
        [claim],
        [],
        []
      );
    await gist.insertGist(
      state2.genesisID,
      state2.getIdenState()
    );
    await circuitCheck(inputs);
    console.log(" Gist Root now = ", gist.getRoot())
  }).timeout(30000);;
});
