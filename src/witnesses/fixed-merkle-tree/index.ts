import { default as MerkleTree } from './FixedMerkleTree.js'
export { MerkleTree }
export default MerkleTree
export type HashFunction = {
  (left: BigInt, right: BigInt): BigInt
}

export type SerializedTreeState = {
  levels: number,
  _zeros: Array<BigInt>,
  _layers: Array<BigInt[]>
}

export type SerializedPartialTreeState = {
  levels: number
  _layers: BigInt[][]
  _zeros: Array<BigInt>
  _edgeLeafProof: ProofPath
  _edgeLeaf: LeafWithIndex
}

export type ProofPath = {
  pathElements: BigInt[],
  pathIndices: number[],
  pathPositions: number[],
  pathRoot: BigInt
}
export type TreeEdge = {
  edgeElement: BigInt;
  edgePath: ProofPath;
  edgeIndex: number;
  edgeElementsCount: number;
}

export type TreeSlice = { edge: TreeEdge, Elements: BigInt[] }
export type LeafWithIndex = { index: number, data: BigInt }

