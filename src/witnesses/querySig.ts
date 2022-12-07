import { Trees } from '../trees/trees.js';
import { signChallenge, SignedChallenge } from '../claim/auth-claim.js';
import { Entry } from '../claim/entry.js';
import { bitsToNum, createMask, getPartialValue } from '../utils.js';
import { compressInputs, createMerkleQueryInput, MerkleQueryInput, OPERATOR } from './query.js';

export interface KYCQuerySigInput {
  readonly issuerClaimSignatureR8x: BigInt;
  readonly issuerClaimSignatureR8y: BigInt;
  readonly issuerClaimSignatureS: BigInt;
  readonly issuerID: BigInt;
  readonly issuerAuthClaim: Array<BigInt>;
  readonly issuerAuthClaimMtp: Array<BigInt>;
  readonly issuerClaimsTreeRoot: BigInt;
  readonly issuerAuthTreeRoot: BigInt;
  readonly issuerState: BigInt;
}
/**
 * KYC service Generate query sig witness for Holder
 * @param {Buffer} privateKey
 * @param {Entry} issuerAuthClaim
 * @param {Entry} issuerClaim
 * @param {Trees} issuerAuthClaimTrees trees of issuer, include issuerClaim
 * @returns {Promise<KYCQuerySigInput>} queryMTP input
 */
export async function kycGenerateQuerySigInput(
  privateKey: Buffer,
  issuerAuthClaim: Entry,
  issuerClaim: Entry,
  issuerAuthClaimTrees: Trees
): Promise<KYCQuerySigInput> {
  const challenge = issuerClaim.getClaimHash();
  const claimSignature = await signChallenge( privateKey, challenge);

  const issuerAuthClaimProof = await issuerAuthClaimTrees.generateProofForAuthClaim(
    issuerAuthClaim.hiRaw()
  );

  return {
    issuerClaimSignatureR8x: claimSignature.challengeSignatureR8x,
    issuerClaimSignatureR8y: claimSignature.challengeSignatureR8y,
    issuerClaimSignatureS: claimSignature.challengeSignatureS,
    issuerID: issuerAuthClaimProof.id,
    issuerAuthClaim: issuerAuthClaim.getDataForCircuit(),
    issuerAuthClaimMtp: issuerAuthClaimProof.claimMTP,
    issuerClaimsTreeRoot: issuerAuthClaimProof.claimsTreeRoot,
    issuerAuthTreeRoot: issuerAuthClaimProof.authTreeRoot,
    issuerState: issuerAuthClaimProof.state
  };
}

export interface QuerySigWitness extends KYCQuerySigInput, SignedChallenge, MerkleQueryInput {
  readonly userID: BigInt;
  readonly userState: BigInt;
  readonly userClaimsTreeRoot: BigInt;
  readonly userAuthClaimMtp: Array<BigInt>;
  readonly userAuthClaim: Array<BigInt>;

  readonly userAuthTreeRoot: BigInt;

  readonly compactInput: BigInt;
  readonly mask: BigInt;

  issuerClaim: Array<BigInt>;
}
/**
 * Holder Generate credential atomic query sig witness from issuer input
 * @param {Entry} issuerClaim
 * @param {Buffer} privateKey
 * @param {Entry} authClaim
 * @param {BigInt} challenge
 * @param {Trees} userAuthTrees
 * @param {KYCQuerySigInput} kycQuerySigInput
 * @param {number} slotIndex
 * @param {OPERATOR} operator
 * @param {Array<BigInt>} values
 * @param {number} valueTreeDepth
 * @param {number} from
 * @param {number} to
 * @param {number} timestamp
 * @returns {Promise<QuerySigWitness>} querySig witness
 */
export async function holderGenerateQuerySigWitness(
  issuerClaim: Entry,
  privateKey: Buffer,
  authClaim: Entry,
  challenge: BigInt,
  userAuthTrees: Trees,
  kycQuerySigInput: KYCQuerySigInput,
  slotIndex: number,
  operator: OPERATOR,
  values: Array<BigInt>,
  valueTreeDepth: number,
  from: number,
  to: number,
  timestamp: number
): Promise<QuerySigWitness> {
  const signature = await signChallenge( privateKey, challenge);
  const authClaimProof = await userAuthTrees.generateProofForAuthClaim(
    authClaim.hiRaw()
  );
  const claimSchema = bitsToNum(issuerClaim.getSchemaHash());
  const compactInput = compressInputs(timestamp, claimSchema, slotIndex, operator);
  const mask = createMask(from, to);
  const slotValue = bitsToNum(issuerClaim.getSlotData(slotIndex));
  const merkleQueryInput = createMerkleQueryInput(
    values,
    valueTreeDepth,
    getPartialValue(slotValue, from, to),
    operator
  );
  return {
    userID: authClaimProof.id,
    userState: authClaimProof.state,
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),
    userAuthTreeRoot: authClaimProof.authTreeRoot,
    compactInput,
    mask,
    ...merkleQueryInput,
    ...kycQuerySigInput,
    issuerClaim: issuerClaim.getDataForCircuit(),
  };
}


/**
 * Holder Generate credential atomic query sig witness from issuer input with signature
 * @param {Entry} issuerClaim
 * @param {SignedChallenge} signature
 * @param {Entry} authClaim
 * @param {Trees} userAuthTrees
 * @param {KYCQuerySigInput} kycQuerySigInput
 * @param {number} slotIndex
 * @param {OPERATOR} operator
 * @param {Array<BigInt>} values
 * @param {number} valueTreeDepth
 * @param {number} from
 * @param {number} to
 * @param {number} timestamp
 * @returns {Promise<QuerySigWitness>} querySig witness
 */
 export async function holderGenerateQuerySigWitnessWithSignature(
  issuerClaim: Entry,
  signature: SignedChallenge,
  authClaim: Entry,
  userAuthTrees: Trees,
  kycQuerySigInput: KYCQuerySigInput,
  slotIndex: number,
  operator: OPERATOR,
  values: Array<BigInt>,
  valueTreeDepth: number,
  from: number,
  to: number,
  timestamp: number
): Promise<QuerySigWitness> {
  const authClaimProof = await userAuthTrees.generateProofForAuthClaim(
    authClaim.hiRaw()
  );
  const claimSchema = bitsToNum(issuerClaim.getSchemaHash());
  const compactInput = compressInputs(timestamp, claimSchema, slotIndex, operator);
  const mask = createMask(from, to);
  const slotValue = bitsToNum(issuerClaim.getSlotData(slotIndex));
  const merkleQueryInput = createMerkleQueryInput(
    values,
    valueTreeDepth,
    getPartialValue(slotValue, from, to),
    operator
  );
  return {
    userID: authClaimProof.id,
    userState: authClaimProof.state,
    ...signature,
    userClaimsTreeRoot: authClaimProof.claimsTreeRoot,
    userAuthClaimMtp: authClaimProof.claimMTP,
    userAuthClaim: authClaim.getDataForCircuit(),
    userAuthTreeRoot: authClaimProof.authTreeRoot,
    compactInput,
    mask,
    ...merkleQueryInput,
    ...kycQuerySigInput,
    issuerClaim: issuerClaim.getDataForCircuit(),
  };
}