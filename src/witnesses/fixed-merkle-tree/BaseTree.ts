import { HashFunction, ProofPath } from './index.js';

export class BaseTree {
  levels: number = 0;
  protected _hashFn: HashFunction = (_left, _right) => BigInt(0);
  protected _zeros: BigInt[] = [];
  protected _layers: Array<BigInt[]> = [];
  protected _zeroElement: BigInt = BigInt(0);

  get capacity() {
    return 2 ** this.levels;
  }

  get layers(): Array<BigInt[]> {
    return this._layers.slice();
  }

  get zeros(): BigInt[] {
    return this._zeros.slice();
  }

  get elements(): BigInt[] {
    return this._layers[0].slice();
  }

  get root(): BigInt {
    return this._layers[this.levels][0] ?? this._zeros[this.levels];
  }

  /**
   * Find an element in the tree
   * @param elements elements of tree
   * @param element An element to find
   * @param comparator A function that checks leaf value equality
   * @param fromIndex The index to start the search at. If the index is greater than or equal to the array's length, -1 is returned
   * @returns {number} Index if element is found, otherwise -1
   */
  static indexOf(
    elements: BigInt[],
    element: BigInt,
    fromIndex?: number,
    comparator?: <T>(arg0: T, arg1: T) => boolean
  ): number {
    if (comparator) {
      return elements.findIndex((el) => comparator<BigInt>(element, el));
    } else {
      return elements.indexOf(element, fromIndex);
    }
  }

  /**
   * Insert new element into the tree
   * @param element BigInt to insert
   */
  insert(element: BigInt) {
    if (this._layers[0].length >= this.capacity) {
      throw new Error('Tree is full');
    }
    this.update(this._layers[0].length, element);
  }

  /*
   * Insert multiple elements into the tree.
   * @param {Array} elements BigInts to insert
   */
  bulkInsert(elements: BigInt[]): void {
    if (!elements.length) {
      return;
    }

    if (this._layers[0].length + elements.length > this.capacity) {
      throw new Error('Tree is full');
    }
    // First we insert all elements except the last one
    // updating only full subtree hashes (all layers where inserted element has odd index)
    // the last element will update the full path to the root making the tree consistent again
    for (let i = 0; i < elements.length - 1; i++) {
      this._layers[0].push(elements[i]);
      let level = 0;
      let index = this._layers[0].length - 1;
      while (index % 2 === 1) {
        level++;
        index >>= 1;
        const left = this._layers[level - 1][index * 2];
        const right = this._layers[level - 1][index * 2 + 1];
        this._layers[level][index] = this._hashFn(left, right);
      }
    }
    this.insert(elements[elements.length - 1]);
  }

  /**
   * Change an element in the tree
   * @param {number} index Index of element to change
   * @param element Updated element value
   */
  update(index: number, element: BigInt) {
    if (isNaN(Number(index)) || index < 0 || index > this._layers[0].length || index >= this.capacity) {
      throw new Error('Insert index out of bounds: ' + index);
    }
    this._layers[0][index] = element;
    this._processUpdate(index);
  }

  /**
   * Get merkle path to a leaf
   * @param {number} index Leaf index to generate path for
   * @returns {{pathElements: Object[], pathIndex: number[]}} An object containing adjacent elements and left-right index
   */
  path(index: number): ProofPath {
    if (isNaN(Number(index)) || index < 0 || index >= this._layers[0].length) {
      throw new Error('Index out of bounds: ' + index);
    }
    let elIndex = +index;
    const pathElements: BigInt[] = [];
    const pathIndices: number[] = [];
    const pathPositions: number[] = [];
    for (let level = 0; level < this.levels; level++) {
      pathIndices[level] = elIndex % 2;
      const leafIndex = elIndex ^ 1;
      if (leafIndex < this._layers[level].length) {
        pathElements[level] = this._layers[level][leafIndex];
        pathPositions[level] = leafIndex;
      } else {
        pathElements[level] = this._zeros[level];
        pathPositions[level] = 0;
      }
      elIndex >>= 1;
    }
    return {
      pathElements,
      pathIndices,
      pathPositions,
      pathRoot: this.root,
    };
  }

  protected _buildZeros() {
    this._zeros = [this._zeroElement];
    for (let i = 1; i <= this.levels; i++) {
      this._zeros[i] = this._hashFn(this._zeros[i - 1], this._zeros[i - 1]);
    }
  }

  protected _processNodes(nodes: BigInt[], layerIndex: number) {
    const length = nodes.length;
    let currentLength = Math.ceil(length / 2);
    const currentLayer = new Array(currentLength);
    currentLength--;
    const starFrom = length - (length % 2 ^ 1);
    let j = 0;
    for (let i = starFrom; i >= 0; i -= 2) {
      if (nodes[i - 1] === undefined) break;
      const left = nodes[i - 1];
      const right = i === starFrom && length % 2 === 1 ? this._zeros[layerIndex - 1] : nodes[i];
      currentLayer[currentLength - j] = this._hashFn(left, right);
      j++;
    }
    return currentLayer;
  }

  protected _processUpdate(index: number) {
    for (let level = 1; level <= this.levels; level++) {
      index >>= 1;
      const left = this._layers[level - 1][index * 2];
      const right =
        index * 2 + 1 < this._layers[level - 1].length
          ? this._layers[level - 1][index * 2 + 1]
          : this._zeros[level - 1];
      this._layers[level][index] = this._hashFn(left, right);
    }
  }
}
