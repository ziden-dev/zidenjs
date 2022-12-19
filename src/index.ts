import bigInt from 'big-integer';
import { HashFunction } from './witnesses/fixed-merkle-tree';
import { MerkleQueryInput } from './witnesses/query';

export const SNARK_SIZE: bigInt.BigNumber = bigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

export interface ZidenParams {
  readonly hasher: Hasher;
  readonly hash0: Hash0;
  readonly hash1: Hash1;
  readonly fmtHash: HashFunction;
  readonly eddsa: EDDSA;
  readonly F: SnarkField;
}
export type Hasher = (arr: Array<BigInt | ArrayLike<number>>) => ArrayLike<number>;
export type Hash0 = (left: BigInt | ArrayLike<number>, right: BigInt | ArrayLike<number>) => ArrayLike<number>;
export type Hash1 = (key: BigInt | ArrayLike<number>, value: BigInt | ArrayLike<number>) => ArrayLike<number>;
export interface SnarkField {
  toObject: (arr: ArrayLike<number>) => BigInt;
  e: (num: BigInt | ArrayLike<number> | number | string) => ArrayLike<number>;
  one: ArrayLike<number>;
  zero: ArrayLike<number>;
  eq: (value1: ArrayLike<number>, value2: ArrayLike<number>) => boolean;
  isZero: (value: ArrayLike<number>) => boolean;
  toString: (value: ArrayLike<number>) => string;
}
export interface EDDSASignature {
  R8: Array<ArrayLike<number>>;
  S: BigInt;
}
export interface EDDSA {
  prv2pub: (privateKey: Buffer) => Array<ArrayLike<number>>;
  signPoseidon: (privateKey: Buffer, msg: ArrayLike<number>) => EDDSASignature;
}

export interface EDDSAPublicKey {
  X: BigInt;
  Y: BigInt;
}

export interface Auth {
  authHi: BigInt;
  pubKey: EDDSAPublicKey;
}

export interface SignedChallenge {
  readonly challenge: BigInt;
  readonly challengeSignatureR8x: BigInt;
  readonly challengeSignatureR8y: BigInt;
  readonly challengeSignatureS: BigInt;
}

export interface IdOwnershipBySignatureWitness extends SignedChallenge {
  readonly userState: BigInt;
  readonly userAuthsRoot: BigInt;
  readonly userAuthMtp: Array<BigInt>;
  readonly userAuthHi: BigInt;
  readonly userAuthPubX: BigInt;
  readonly userAuthPubY: BigInt;
  readonly userAuthRevRoot: BigInt;
  readonly userAuthNonRevMtp: Array<BigInt>;
  readonly userAuthNonRevMtpNoAux: BigInt;
  readonly userAuthNonRevMtpAuxHi: BigInt;
  readonly userAuthNonRevMtpAuxHv: BigInt;
  readonly userClaimsRoot: BigInt;
  readonly userClaimRevRoot: BigInt;
}

export interface StateTransitionWitness {
  readonly userID: BigInt;
  readonly oldUserState: BigInt;
  readonly newUserState: BigInt;
  readonly isOldStateGenesis: number;

  readonly userAuthsRoot: BigInt;
  readonly userAuthMtp: Array<BigInt>;
  readonly userAuthHi: BigInt;
  readonly userAuthPubX: BigInt;
  readonly userAuthPubY: BigInt;
  readonly userAuthRevRoot: BigInt;
  readonly userAuthNonRevMtp: Array<BigInt>;
  readonly userAuthNonRevMtpNoAux: BigInt;
  readonly userAuthNonRevMtpAuxHi: BigInt;
  readonly userAuthNonRevMtpAuxHv: BigInt;
  readonly userClaimsRoot: BigInt;
  readonly userClaimRevRoot: BigInt;

  readonly challengeSignatureR8x: BigInt;
  readonly challengeSignatureR8y: BigInt;
  readonly challengeSignatureS: BigInt;
}

export interface KYCQueryMTPInput {
  readonly issuerClaimMtp: Array<BigInt>;
  readonly issuerClaimAuthsRoot: BigInt;
  readonly issuerClaimClaimsRoot: BigInt;
  readonly issuerClaimAuthRevRoot: BigInt;
  readonly issuerClaimClaimRevRoot: BigInt;
  readonly issuerClaimIdenState: BigInt;
  readonly issuerID: BigInt;
}

export interface KYCNonRevQueryMTPInput {
  readonly issuerClaimNonRevMtp: Array<BigInt>;
  readonly issuerClaimNonRevMtpNoAux: BigInt;
  readonly issuerClaimNonRevMtpAuxHi: BigInt;
  readonly issuerClaimNonRevMtpAuxHv: BigInt;
  readonly issuerClaimNonRevAuthsRoot: BigInt;
  readonly issuerClaimNonRevClaimsRoot: BigInt;
  readonly issuerClaimNonRevAuthRevRoot: BigInt;
  readonly issuerClaimNonRevClaimRevRoot: BigInt;
  readonly issuerClaimNonRevState: BigInt;
}

export enum OPERATOR {
  NOOP,
  EQUAL,
  LESS_THAN,
  GREATER_THAN,
  IN,
  NOT_IN,
  IN_RANGE,
}

export interface Query {
  slotIndex: number;
  operator: OPERATOR;
  values: Array<BigInt>;
  valueTreeDepth: number;
  from: number;
  to: number;
  timestamp: number;
  claimSchema: BigInt;
}

export interface QueryMTPWitness
  extends KYCQueryMTPInput,
    KYCNonRevQueryMTPInput,
    IdOwnershipBySignatureWitness,
    MerkleQueryInput {
  readonly timestamp: number;
  readonly claimSchema: BigInt;
  readonly slotIndex: number;
  readonly operator: OPERATOR;
  readonly mask: BigInt;
  readonly issuerClaim: Array<BigInt>;
  readonly userID: BigInt;
}

export * as params from './global.js';
export * as utils from './utils.js';
export * as claim from './claim/entry.js';
export * as id from './claim/id.js';
export * as auth from './state/auth.js';
export * as state from './state/state.js';
export * as idOwnership from './witnesses/authentication.js';
export * as stateTransition from './witnesses/stateTransition.js';
export * as queryMTP from './witnesses/queryMTP.js';
