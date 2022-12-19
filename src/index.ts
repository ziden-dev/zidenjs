import { MerkleQueryInput } from './witnesses/query';

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
  readonly issuerClaim: Array<BigInt>,
  readonly userID: BigInt
}
