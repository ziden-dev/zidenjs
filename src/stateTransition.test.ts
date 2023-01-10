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
  let authRevDb: SMTLevelDb;
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
    authRevDb = new SMTLevelDb('src/db_test/authRev');
    claimRevDb = new SMTLevelDb('src/trees/claimRev');

    state = await State.generateState([auth1], authsDb, claimsDb, authRevDb, claimRevDb);

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
  }).timeout(100000);

  it('1st state transition', async () => {
    const w1 = await stateTransitionWitnessWithPrivateKey(priv1, auth1, state, [auth2], [claim1, claim2], [], []);
    // console.log(w1)

    const inputs = {
      userID: BigInt('69249257860944330745233591343151389524778481505914547330234771236614504448'),
      oldUserState: BigInt('17727810012401748670779799383846755718343291265514124116540101436573316813338'),
      newUserState: BigInt('11612959936571582521769292815910197952416589076667910820802958695081967811861'),
      isOldStateGenesis: 1,
      userAuthsRoot: BigInt('20627049691074211306515453210938057343527170503262277195053064909938340298877'),
      userAuthMtp: [
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
      ],
      userAuthHi: BigInt(0),
      userAuthPubX: BigInt('10405297922989122246950340928233997470981486801684436631700061692699411603256'),
      userAuthPubY: BigInt('15763765606440274408775952854963881333920541706136331067967613150434046648956'),
      userAuthRevRoot: BigInt('0'),
      userAuthNonRevMtp: [
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
        BigInt(0),
      ],
      userAuthNonRevMtpNoAux: BigInt(1),
      userAuthNonRevMtpAuxHi: BigInt(0),
      userAuthNonRevMtpAuxHv: BigInt(0),
      userClaimsRoot: BigInt(0),
      userClaimRevRoot: BigInt(0),
      challengeSignatureR8x: BigInt('14438518890504357322673274663601653696881664869980158450433131888564068033696'),
      challengeSignatureR8y: BigInt('15628489061854613618725252458077455132547292092733672686559809064134908873757'),
      challengeSignatureS: BigInt('2106436037731130480459515962232792246233548164059004434823164340025097499450'),
    };
    w1;
    console.log(inputs);
    await circuitCheck(inputs);
  }).timeout(20000);

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
  }).timeout(30000);
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
