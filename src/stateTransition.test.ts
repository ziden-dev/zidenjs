// @ts-ignore
import { wasm as wasm_tester } from 'circom_tester';
// @ts-ignore
import { groth16 } from 'snarkjs';
import path from 'path';
import {
  Entry,
  newClaim,
  schemaHashFromBigInt,
  withExpirationDate,
  withIndexData,
  withSlotData,
} from './claim/entry.js';
import { Auth, StateTransitionWitness } from './index.js';
import { State } from './state/state.js';
import { SMTLevelDb } from './db/index.js';
import { setupParams } from './global.js';
import { newAuthFromPrivateKey } from './state/auth.js';
import {
  stateTransitionWitnessWithPrivateKey,
  stateTransitionWitnessWithPrivateKeyAndHiHvs,
} from './witnesses/stateTransition.js';

describe('test state transition', async () => {
  let priv1: Buffer;
  let priv2: Buffer;
  let priv3: Buffer;

  let auth1: Auth;
  let auth2: Auth;
  let auth3: Auth;

  let claim1: Entry;
  let claim2: Entry;
  let claim3: Entry;
  let claim4: Entry;
  let claim5: Entry;

  let state: State;
  let authsDb: SMTLevelDb;
  let claimsDb: SMTLevelDb;
  let claimRevDb: SMTLevelDb;

  let circuitCheck: (witness: StateTransitionWitness) => Promise<void>;
  it('set up trees and claims', async () => {
    await setupParams();
    priv1 = Buffer.alloc(32, 1);
    priv2 = Buffer.alloc(32, 2);
    priv3 = Buffer.alloc(32, 3);

    auth1 = newAuthFromPrivateKey(priv1);
    auth2 = newAuthFromPrivateKey(priv2);
    auth3 = newAuthFromPrivateKey(priv3);

    authsDb = new SMTLevelDb('src/db_test/auths');
    claimsDb = new SMTLevelDb('src/db_test/claims');
    claimRevDb = new SMTLevelDb('src/db_test/claimRev');

    state = await State.generateState([auth1], authsDb, claimsDb, claimRevDb);

    claim1 = newClaim(
      schemaHashFromBigInt(BigInt('12345')),
      withSlotData(7, Buffer.alloc(30, 2)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim2 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 2), Buffer.alloc(30, 3)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim3 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 3), Buffer.alloc(30, 4)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim4 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 4), Buffer.alloc(30, 5)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    claim5 = newClaim(
      schemaHashFromBigInt(BigInt('123456')),
      withIndexData(Buffer.alloc(30, 5), Buffer.alloc(30, 6)),
      withExpirationDate(BigInt(Date.now() + 100000))
    );
    circuitCheck = async (witness: StateTransitionWitness) => {
      const circuit = await wasm_tester(path.join('src', 'circom_test', 'stateTransition.circom'));
      const w = await circuit.calculateWitness(witness, true);
      await circuit.checkConstraints(w);
    };
  })

  it('1st state transition', async () => {
    const w1 = await stateTransitionWitnessWithPrivateKey(priv1, auth1, state, [auth2], [claim1, claim2], [], []);
    //console.log(inputs);
    await circuitCheck(w1);
  })

  it('2nd state transition', async () => {
    claim3 = await state.prepareClaimForInsert(claim3);
    claim4 = await state.prepareClaimForInsert(claim4);
    const w2 = await stateTransitionWitnessWithPrivateKeyAndHiHvs(
      priv2,
      auth2,
      state,
      [],
      [
        [claim3.hiRaw(), claim3.hvRaw()],
        [claim4.hiRaw(), claim4.hvRaw()],
      ],
      [],
      [claim1.getRevocationNonce(), claim2.getRevocationNonce()]
    );
    await circuitCheck(w2);
  })
  let witness: StateTransitionWitness;
  it('3rd state transition', async () => {
    witness = await stateTransitionWitnessWithPrivateKey(
      priv1,
      auth1,
      state,
      [auth3],
      [claim5],
      [auth1.authHi, auth2.authHi],
      [claim3.getRevocationNonce()]
    );
    console.log(witness.isOldStateGenesis);
  });

  // it('benchmark proving time', async () => {

  //   await groth16.fullProve(witness, 'src/circom_test/stateTransition.wasm', 'src/circom_test/stateTransition.zkey');
  // }).timeout(100000);
});
