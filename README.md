# Zidenjs *(Internal version)*

> Core library for interacting with **Ziden** protocol, support all functions for **holders**, **issuers** and **verifiers**

## Library structure

1. [Claim](https://github.com/ziden-dev/zidenjs/tree/dev/src/claim) - defines and interacts with claims, includes **generic claim**, **auth claim** and **id**

2. [Database](https://github.com/ziden-dev/zidenjs/tree/dev/src/db) - provides an interface for **sparse merkle tree database** and a concrete implementation using **level db**

3. [Trees](https://github.com/ziden-dev/zidenjs/tree/dev/src/trees) - provides interface for **sparse merkle tree** and 2 conrete implementations (**binary** and **quinary**), constructs a complete identity from 3 sparse merkle trees: **claims**, **revocation** and **roots**, generates **merkle proofs**

4. [Witnesses](https://github.com/ziden-dev/zidenjs/tree/dev/src/witnesses) - supports generate inputs for circuits used in **Ziden** includes **query MTP**, **query Sig**, **id ownership by signature**, **state transition**

5. [Global](https://github.com/ziden-dev/zidenjs/blob/dev/src/global.ts) - declares some types and functions to construct parameters which be used throughout the library

## Usage

### 1. Initialize global parameters

Precompute all global parameters and store them somewhere in your program. You may need to use them often

```typescript
import { global as zidenParams } from 'zidenjs';

// construct Bn128 prime field
const F = await zidenParams.buildSnarkField();
// constructs Poseidon hasher
const hasher = await zidenParams.buildHasher();
// constructs EDDSA Signer
const eddsa = await zidenParams.buildSigner();
// constructs Hash0, Hash1 functions used in Sparse Merkle Tree
const { hash0, hash1 } = await zidenParams.buildHash0Hash1(hasher, F);

// You should store (F, hasher, eddsa, hash0, hash1) here
```

### 2. Claims

Module [Claim](https://github.com/ziden-dev/zidenjs/tree/dev/src/claim) provides some utilities to construct and interact with **Claims**

##### Examples

```typescript
import { claim, utils } from 'zidenjs';
const {
  newClaim,
  withExpirationDate,
  withFlagUpdatable,
  withFlagExpirable,
  withIndexData,
  withValueData,
  withIndexID,
  withRevocationNonce,
  withID,
  schemaHashFromBigInt,
  Entry 
} = claim.entry;
// Load (F, hasher, eddsa ) from your storage

// Each claim requires a schema hash which is hash result of claim structure definition
const schemaHash = schemaHashFromBigInt(BigInt('304427537360709784173770334266246861770'));

// construct a claim without any information
const claim0 = newClaim(schemaHash);

// construct a claim with expiration date and revocation nonce
const expirationDate = BigInt(123456);
const revocationNonce = BigInt(111);
const expirableFlag = true;

const claim1 = newClaim(
    schemaHash, 
    withFlagExpirable(expirableFlag), 
    withExpirationDate(expirationDate), 
    withRevocationNonce(revocationNonce)
);

// construct a claim with many information
const privateKey = crypto.randomBytes(32);
const pubkey = eddsa.prv2pub(privateKey);
const pubkeyX = F.toObject(pubkey[0]);
const pubkeyY = F.toObject(pubkey[1]);
const updatableFlag = true;
const otherID = Buffer.alloc(31, 1);
const valueAData = Buffer.alloc(30, 4);
const valueBData = Buffer.alloc(30, 5);

const claim2 = newClaim(
    schemaHash,
    withFlagExpirable(expirableFlag),
    withFlagUpdatable(updatableFlag),
    withExpirationDate(expirationDate),
    withRevocationNonce(revocationNonce),
    withIndexID(otherID),
    withIndexData(utils.numToBits(pubkeyX, 32), utils.numToBits(pubkeyY, 32)),
    withValueData(valueAData, valueBData)
);

// you can also update claim
claim2.setRevocationNonce(BigInt(1));
claim.setVersion(BigInt(0));
```
##### Auth claim (special claim which represents public-private eddsa key pair)

```typescript
// construct an auth claim from a random private key
import crypto from 'crypto';
import { claim } from 'zidenjs';

const privateKey = crypto.randomBytes(32);
const authClaim = await claim.authClaim.newAuthClaimFromPrivateKey(eddsa, F, privateKey);
```

##### Sign a challenge with private key

```typescript
// construct an auth claim from a random private key
import crypto from 'crypto';
import { claim } from 'zidenjs';
const {signChallenge, SignedSignature} = claim.authClaim;
const privateKey = crypto.randomBytes(32);
const challenge = BigInt('4893740132');

const signature: SignedSignature = await signChallenge(
  eddsa,
  F,
  privateKey,
  challenge
)
```
### 3. Generate Identity

An identity is constructed from some **auth claims**. There are two Sparse Merkle Tree structures currently be supported by Ziden. The default one is **Quinary SMT** with depth of **14** (**highly recommended**), and another is **Binary SMT** with depth of **32**

##### Example

```typescript
import {trees, db, claim} from 'zidenjs';

const {SMTLevelDb} = db;
const {Trees, SMTType} = trees;
const {IDType} = claim.id;
// Specify data base to store claims, revocation and roots trees. 
const claimsDb = new SMTLevelDb('path/to/your/claims-tree-db', F);
const revocationDb = new SMTLevelDb('path/to/your/revocation-tree-db', F);
const rootsDb = new SMTLevelDb('path/to/your/roots-tree-db', F);

// Quinary SMT (default option, don't need to specify SMT type and depth)
const idWithQSMT = await Trees.generateID(
    F, 
    hash0,
    hash1,
    hasher, 
    [authClaim],
    claimsDb,
    revocationDb,
    rootsDb,
    IDType.Default
);

// Binary SMT (need to specify SMT type and depth)
const idWithBSMT = await Trees.generateID(
    F,
    hash0,
    hash1,
    hasher,
    [authClaim],
    claimsDb,
    revocationDb,
    rootsDb,
    IDType.Default,
    32,
    SMTType.BinSMT
);
```

### 4. Update State

The state of an identity can be updated by **issuing new claims** or **revoking invalid ones**.

#### With private key

```typescript
import { groth16 } from 'snarkjs';
import { witnesses } from 'zidenjs';

// update your trees and calculate inputs for state transition circuits in a same time
const witness = await witnesses.stateTransitionWitness(
    eddsa,
    privateKey,
    authClaim,
    trees,
    [claim0, claim1, claim2], // list of inserting claims
    [claim3.getRevocationNonce(), claim4.getRevocationNonce()], // list of revoking claim revocation nonces
    hasher
);

// optional - calculate zero knowledge proof from generated witness with snarkjs
const {proof, publicSignals} = await groth16.fullProve(witness,
    'path/to/your/wasm-file', 'path/to/your/zkey-file'
);
```

#### With Hi-Hv and the revocation nonce of claims (if issuer doesn't access to raw claims)

```typescript
import { groth16 } from 'snarkjs';
import { witnesses, claim } from 'zidenjs';

// update your trees and calculate inputs for state transition circuits in a same time
const witness = await witnesses.stateTransitionWitnessWithHiHv(
    signature,
    authClaim,
    trees,
    [claim0, claim1, claim2], // list of inserting claims
    [claim3.getRevocationNonce(), claim4.getRevocationNonce()], // list of revoking claim revocation nonces
    hasher
);

// optional - calculate zero knowledge proof from generated witness with snarkjs
const {proof, publicSignals} = await groth16.fullProve(witness,
    'path/to/your/wasm-file', 'path/to/your/zkey-file'
);
```
### 5. Credential atomic query MTP

#### Issuer side - calculates claim exists MTP (private) and non-rev MTP (public) and sends it to holder

```typescript
import { witnesses } from 'zidenjs';

// issuer Trees: trees of issuer
// holder Trees: trees of holder
// given that issuer had issued issuerClaim for holder 

// calculates claim exists MTP (private data, need to encrypt the input before sending it to holder) 
const kycQueryMTPInput = await witnesses.kycGenerateQueryMTPInput(issuerClaim.hiRaw(issuerTrees.hasher), issuerTrees);

// calculates claim non rev MTP
const kycQueryNonRevMTPInput = await witnesses.kycGenerateNonRevQueryMTPInput(issuerClaim.getRevocationNonce(), issuerTrees);
```

#### Holder side - calculates complete input for query MTP circuit based on 2 inputs from issuer and their claim information

```typescript
import { witnesses, claim } from 'zidenjs';

const values = [BigInt(20010210)];

// the challenge value is specified by attestators
const challenge = BigInt('12345');

const witness = await holderGenerateQueryMTPWitness(
    issuerClaim,
    eddsa,
    holderPrivateKey,
    holderAuthClaim,
    challenge,
    holderTrees,
    kycQueryMTPInput,
    kycQueryNonRevMTPInput,
    2, // slot index
    witnesses.query.OPERATOR.LESS_THAN, // operator
    values,
    10, 
    0,
    100,
    hashFunction,
    F
);

// use witness to generate zk proof here
```


### 6. Credential atomic query Sig

#### Issuer side - calculates claim signature (private) and non-rev MTP (public) and sends it to holder

```typescript
import { witnesses } from 'zidenjs';

// issuer Trees: trees of issuer
// holder Trees: trees of holder
// issuers don't need to add the claim to their claims tree

// calculates claim signature (private data, need to encrypt the input before sending it to holder) 
const kycQuerySigInput = await kycGenerateQuerySigInput(
    eddsa,
    hasher,
    issuerPrivateKey,
    issuerAuthClaim,
    issuerClaim,
    issuerTrees
);

// calculates claim non rev MTP
const kycQuerySigNonRevInput = await kycGenerateQuerySigNonRevInput(issuerClaim.getRevocationNonce(), issuerTrees);
```

#### Holder side - calculates complete input for query Sig circuit based on 2 inputs from issuer and their claim information

```typescript
import { witnesses, claim } from 'zidenjs';

const values = [BigInt(20010210)];

// the challenge value is specified by attestators
const challenge = BigInt('12345');

const witness = await holderGenerateQuerySigWitness(
    issuerClaim,
    eddsa,
    holderPrivateKey,
    holderAuthClaim,
    challenge,
    holderTrees,
    kycQuerySigInput,
    kycQuerySigNonRevInput,
    2,
    witnesses.query.OPERATOR.LESS_THAN,
    values,
    10,
    0,
    100,
    hashFunction,
    F
);

// use witness to generate zk proof here
```