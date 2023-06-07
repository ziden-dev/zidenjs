import { getZidenParams } from '../global.js';
import MerkleTree from './fixed-merkle-tree/index.js';
import { OPERATOR } from '../index.js';

export interface MerkleQueryInput {
  readonly determinisiticValue: BigInt;
  readonly leaf0: BigInt;
  readonly leaf1: BigInt;
  readonly elemsPath0: Array<BigInt>;
  readonly pos0: BigInt;
  readonly elemsPath1: Array<BigInt>;
  readonly pos1: BigInt;
}

const ErrInvalidValues = new Error('Invalid values');
/**
 * Create merkle query input for query circuits from values
 * @category query
 * @param {Array<BigInt>} values
 * @param {number} valueTreeDepth
 * @param {BigInt} attestingValue
 * @param {OPERATOR} operator
 * @returns {MerkleQueryInput} input for circuits
 */
export function createMerkleQueryInput(
  values: Array<BigInt>,
  valueTreeDepth: number,
  attestingValue: BigInt,
  operator: OPERATOR
): MerkleQueryInput {
  let determinisiticValue: BigInt = BigInt(0);
  let leaf0: BigInt = BigInt(0);
  let leaf1: BigInt = BigInt(0);
  let pos0: BigInt = BigInt(0);
  let pos1: BigInt = BigInt(0);
  let elemsPath0: Array<BigInt> = Array(valueTreeDepth).fill(BigInt(0));
  let elemsPath1: Array<BigInt> = Array(valueTreeDepth).fill(BigInt(0));
  if (operator === OPERATOR.NOOP) {
    // NO-OP OPERATOR, don't need to specify merkle query input (do nothing)
  } else if (operator >= OPERATOR.EQUAL && operator <= OPERATOR.GREATER_THAN) {
    // Single OPERATOR require the array of values must has only 1 element.
    if (values.length !== 1) {
      throw ErrInvalidValues;
    }
    switch (operator) {
      // EQUAL OPERATOR
      case OPERATOR.EQUAL: {
        if (values[0] !== attestingValue) {
          throw ErrInvalidValues;
        }
        break;
      }
      // LESS THAN OPERATOR
      case OPERATOR.LESS_THAN: {
        if (values[0] <= attestingValue) {
          throw ErrInvalidValues;
        }
        break;
      }
      // GREATOR THAN OPERATOR
      case OPERATOR.GREATER_THAN: {
        if (values[0] >= attestingValue) {
          throw ErrInvalidValues;
        }
        break;
      }
    }
    determinisiticValue = values[0];
  } else {
    // OPERATOR 4 (IN), 5 (NOT IN), 6 (IN RANGE) need to build fixed merkle tree from sorted array of values
    const valueArraySize = 1 << valueTreeDepth;
    const sortedValues = values.slice();
    sortedValues.sort();
    const biggestValue = sortedValues[values.length - 1];

    // pad the sortedValues to fill valueArraySize
    for (let i = values.length; i < valueArraySize; i++) {
      sortedValues.push(biggestValue);
    }
    const fmt = new MerkleTree(
      valueTreeDepth,
      sortedValues,
      getZidenParams().fmtHash,
      getZidenParams().F.toObject(getZidenParams().F.zero)
    );
    // find the smallest value in array which greater than the attesting value
    const greaterIndex = sortedValues.findIndex((value) => value > attestingValue);

    if (operator === OPERATOR.IN_RANGE) {
      // IN RANGE Operator, we must prove values[0] < attestingValue < values[1]
      if (values.length !== 2 || values[0] >= attestingValue || values[1] <= attestingValue) {
        throw ErrInvalidValues;
      }
      leaf0 = values[0];
      leaf1 = values[1];
    } else {
      // check that attesting value is exist in the array of values ( for IN OPERATOR )
      const equalResult = sortedValues.find((value) => value === attestingValue);

      if (operator === OPERATOR.IN) {
        if (!equalResult) {
          throw ErrInvalidValues;
        }
        // IN OPERATOR, we don't need construct merkle tree proof for leaf 1
        leaf0 = equalResult;
      } else {
        // NOT IN
        // assert that the attesting value is not exist in the array of values
        if (equalResult) {
          throw ErrInvalidValues;
        }

        // Case 1: the attesting value is less than the leaf most leaf, construct merkle tree proof for leaf0 (the left most leaf)
        if (greaterIndex === 0) {
          leaf0 = sortedValues[0];
        } else if (greaterIndex === -1) {
          // Case 2: the attesting value is greater than the right most leaf, construct merkle tree proof for leaf1 (the right most leaf)
          leaf1 = sortedValues[sortedValues.length - 1];
        } else {
          // Case 3: the atessting value is between 2 consecutive leaves in merkle tree
          leaf0 = sortedValues[greaterIndex - 1];
          leaf1 = sortedValues[greaterIndex];
        }
      }
    }

    if (greaterIndex !== -1 || operator === OPERATOR.IN) {
      // Construct Merkle Tree Proof for leaf0
      const leaf0Proof = fmt.proof(leaf0);
      elemsPath0 = leaf0Proof.pathElements;

      leaf0Proof.pathIndices;
      let temp0 = BigInt(0);
      for (let i = 0; i < valueTreeDepth; i++) {
        if (leaf0Proof.pathIndices[i] === 1) temp0 += BigInt(1) << BigInt(i);
      }
      pos0 = temp0;
      determinisiticValue = leaf0Proof.pathRoot;
    }
    if (operator !== OPERATOR.IN && greaterIndex !== 0) {
      // Construct Merkle Tree Proof for leaf1
      const leaf1Proof = fmt.proof(leaf1, greaterIndex === -1 ? sortedValues.length - 1 : undefined);
      elemsPath1 = leaf1Proof.pathElements;
      leaf1Proof.pathIndices;
      let temp1 = BigInt(0);
      for (let i = 0; i < valueTreeDepth; i++) {
        if (leaf1Proof.pathIndices[i] === 1) temp1 += BigInt(1) << BigInt(i);
      }
      pos1 = temp1;
      determinisiticValue = leaf1Proof.pathRoot;
    }
  }

  return {
    determinisiticValue,
    leaf0,
    leaf1,
    pos0,
    pos1,
    elemsPath0,
    elemsPath1,
  };
}

/**
 * Calculate deterministicValue from values and operator
 * @category query
 * @param {Array<BigInt>} values
 * @param {number} valueTreeDepth
 * @param {OPERATOR} operator
 * @returns {BigInt}
 */
export function calculateDeterministicValue(values: Array<BigInt>, valueTreeDepth: number, operator: OPERATOR): BigInt {
  if (operator === OPERATOR.NOOP) return BigInt(0);
  if (operator < OPERATOR.IN) {
    return values[0];
  }
  // OPERATOR 4 (IN), 5 (NOT IN), 6 (IN RANGE) need to build fixed merkle tree from sorted array of values
  const valueArraySize = 1 << valueTreeDepth;
  const sortedValues = values.slice();
  sortedValues.sort();
  const biggestValue = sortedValues[values.length - 1];

  // pad the sortedValues to fill valueArraySize
  for (let i = values.length; i < valueArraySize; i++) {
    sortedValues.push(biggestValue);
  }
  const fmt = new MerkleTree(
    valueTreeDepth,
    sortedValues,
    getZidenParams().fmtHash,
    getZidenParams().F.toObject(getZidenParams().F.zero)
  );

  return fmt.root;
}