# Zidenjs

> Core library for interacting with **Ziden** protocol, supports all functions for **holders**, **issuers** and **verifiers**

## Installation

```
npm i
```

## Test

```
npm run test-all
```

## Generate Documents

```
npm run gen-doc
```

## Build

```
npm run build
```

## Usages

### Setup Parameters

Some functions of the library require cryptograhic operators that require time to setup. To optimize your application, you should call the setup function for them first as precomputation.

```typescript
import { params } from '@zidendev/zidenjs';

await params.setupParams();
```

### Create Keys for Authorization

The keys created can be later used to construct your identity

In the following example, the private key is created randomly, you may want to utilize some key generation techniques to make it more secure and easier to manage.

```typescript
import { auth } from '@zidendev/zidenjs';
import { randomBytes } from 'crypto';

const privateKey = randomBytes(32);
const auth = await auth.newAuthFromPrivateKey(privateKey);
```

### Generate Identity from created auths

```typescript
import { auth, db, state } from '@zidendev/zidenjs';
import { randomBytes } from 'crypto';

const privateKey = randomBytes(32);
const auth = await auth.newAuthFromPrivateKey(privateKey);

// setup level DB to store trees
const authDb = smt.SMTLevelDb('/path/to/your/authDb');
const claimDb = smt.SMTLevelDb('/path/to/your/claimDb');
const claimRevDb = smt.SMTLevelDb('/path/to/your/claimRevDb');

const identity = await state.State.generateState([auth], authDb, claimDb, claimRevDb);
```

### Create claims

```typescript
import { claim } from '@zidendev/zidenjs';
const { newClaim, schemaHashFromBigInt, withIndexData, withExpirationDate } = claim;

const claim = newClaim(
  schemaHashFromBigInt(BigInt('123456')),
  withIndexData(Buffer.alloc(30, 5), Buffer.alloc(30, 6)),
  withExpirationDate(BigInt(Date.now() + 100000))
);
```

### State Transition

The witness returned from the **stateTransition** function will be passed as input into the **stateTransion** circuit </br>

State Transition relates to inserting new Auths, Claims or revoking invalid Auths, Claims

```typescript
import { stateTransition } from '@zidendev/zidenjs';

const witness = await stateTransition.stateTransitionWitnessWithPrivateKey(
  priv1,
  auth,
  state,
  [insertedAuth],
  [insertedClaim],
  [revokedAuth1.authHi, revokedAuth2.authHi],
  [revokedClaim.getRevocationNonce()]
);
```

### Query MTP

Holding a certain claim with some qualities, the holder can demonstrate these qualities by using functions provide by **queryMTP** module

```typescript
import { queryMTP, claim, auth } from '@zidendev/zidenjs';
const { newClaim, schemaHashFromBigInt, withSlotData, withIndexID } = claim;

const holderPrivateKey = // mock here
const holderAuth = await auth.newAuthFromPrivateKey(holderPrivateKey);
const query1 = {
  slotIndex: 2,
  operator: OPERATOR.LESS_THAN,
  values: [BigInt(20040101)],
  valueTreeDepth: 6,
  from: 10,
  to: 100,
  timestamp: Date.now(),
  claimSchema: BigInt(12394),
};

const slot1 = setBits(BigInt(0), query1.from, BigInt(20010101));

const claim1 = newClaim(
  schemaHashFromBigInt(query1.claimSchema),
  withSlotData(query1.slotIndex, numToBits(slot1, 32)),
  withIndexID(holderState.userID)
);

// issuer side: grant kycGenerateQueryMTPInput for holder once issued
const kycQueryMTPInput = await kycGenerateQueryMTPInput(claim1.hiRaw(), issuerState);

// issuer side: grant kycGenerateNonRevQueryMTPInput for holder when asked
const kycNonRevQueryMTPInput = await kycGenerateNonRevQueryMTPInput(claim1.getRevocationNonce(), issuerState);
// holder side: generate queryMTP proof on their claim
const witness = await holderGenerateQueryMTPWitnessWithPrivateKey(
  claim1,
  holderPrivateKey,
  holderAuth,
  BigInt(1),
  holderState,
  kycQueryMTPInput,
  kycNonRevQueryMTPInput,
  query1
);
```

**For more detailed codes, please refer to test files in the library**
