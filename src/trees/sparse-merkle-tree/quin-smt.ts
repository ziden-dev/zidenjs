import { getZidenParams } from '../../global.js';
import { SMTDb } from '../../db/index.js';
import SMT, { DeletingResult, FindingResult, InsertingResult, Primitive, UpdatingResult } from './index.js';

export class QuinSMT implements SMT {
  private _db: SMTDb;
  private _root: ArrayLike<number>;
  private _maxLevels: number;
  constructor(db: SMTDb, root: ArrayLike<number>, maxLevels: number) {
    this._db = db;
    this._root = root;
    this._maxLevels = maxLevels;
  }

  get db(): SMTDb {
    return this._db;
  }
  get root(): ArrayLike<number> {
    return this._root;
  }

  private _splitQuins(_key: ArrayLike<number>): Array<number> {
    const F = getZidenParams().F;
    let E = F.toObject(_key).valueOf();
    let res = [];
    while (E) {
      res.push(parseInt((E % BigInt(5)).toString()));
      E = E / BigInt(5);
    }

    while (res.length < this._maxLevels) res.push(0);

    return res;
  }

  /**
   * update a leaf of SMT, if the leaf with oldValue is not exist, insert the leaf into SMT
   * @param {Primitive} _key index of the updating leaf
   * @param {Primitive} _newValue new value of the updating leaf
   * @returns {Promise<UpdatingResult>} information about new root, siblings of the leaf after updating
   */
  async update(_key: Primitive, _newValue: Primitive): Promise<UpdatingResult> {
    const F = getZidenParams().F;
    const key = F.e(_key);
    const newValue = F.e(_newValue);

    const resFind = await this.find(key);
    const res: UpdatingResult = {
      oldRoot: this._root,
      newRoot: F.zero,
      oldKey: key,
      oldValue: resFind.foundValue,
      newKey: key,
      newValue,
      siblings: resFind.siblings,
    };

    const ins: [ArrayLike<number>, Primitive[]][] = [];
    const dels: ArrayLike<number>[] = [];

    let rtOld = getZidenParams().hash1(key, resFind.foundValue!);
    let rtNew = getZidenParams().hash1(key, newValue);
    ins.push([rtNew, [1, key, newValue]]);
    dels.push(rtOld);

    const keyQuins = this._splitQuins(key);
    for (let level = resFind.siblings.length / 4 - 1; level >= 0; level--) {
      const index = keyQuins[level];

      const oldNode = resFind.siblings.slice(4 * level, 4 * level + 4);
      oldNode.splice(index, 0, rtOld);
      const newNode = resFind.siblings.slice(4 * level, 4 * level + 4);
      newNode.splice(index, 0, rtNew);
      rtOld = getZidenParams().hasher(oldNode);
      rtNew = getZidenParams().hasher(newNode);
      dels.push(rtOld);
      ins.push([rtNew, newNode]);
    }

    res.newRoot = rtNew;

    await this._db.multiDel(dels);
    await this._db.multiIns(ins);
    await this._db.setRoot(rtNew);
    this._root = rtNew;

    return res;
  }

  /**
   * delete a new leaf from SMT, asserted that leaf is exist in SMT
   * @param {Primitive} _key index of the deleting leaf
   * @returns {Promise<DeletingResult>} information about new root, siblings of the leaf after inserting to SMT
   */
  async delete(_key: Primitive): Promise<DeletingResult> {
    const F = getZidenParams().F;
    const key = F.e(_key);

    const resFind = await this.find(key);
    if (!resFind.found) throw new Error('Key does not exists');

    const res: DeletingResult = {
      siblings: [],
      delKey: key,
      delValue: resFind.foundValue!,
      oldRoot: this._root,
      newRoot: F.zero,
      isOld0: true,
    };

    const ins: [ArrayLike<number>, Primitive[]][] = [];
    const dels: ArrayLike<number>[] = [];
    let rtOld = getZidenParams().hash1(key, resFind.foundValue!);
    let rtNew = F.zero;
    dels.push(rtOld);

    let mixed;
    if (resFind.siblings.length % 4 !== 0) throw new Error('Invalid sibling list');
    if (resFind.siblings.length > 0) {
      /* It must be in one of 2 cases:
       - Case 1: only one of the 4 siblings of the deleting leaf is a leaf, all remainings are zero => mixed is false, push that leaf up and recalculate the acients.
       - Case 2: the deleting leaf has at least 2 non zero siblings or at least 1 internal node sibling => mixed is true, just recalculate the acients. 
    */
      const leafSiblings = resFind.siblings.slice(resFind.siblings.length - 4);
      let nonZeroCount = 0;
      for (let j = 0; j < 4; j++) {
        if (!F.isZero(leafSiblings[j])) {
          const record = await this._db.get(leafSiblings[j]);
          if (!record) {
            throw new Error('Record not found in db');
          }
          nonZeroCount++;
          if (nonZeroCount > 1 || record.length === 5) {
            mixed = true;
            res.oldKey = key;
            res.oldValue = F.zero;
            res.isOld0 = true;
            rtNew = F.zero;
            break;
          } else if (record.length === 3 && F.eq(record[0], F.one)) {
            mixed = false;
            res.oldKey = record[1];
            res.oldValue = record[2];
            res.isOld0 = false;
            rtNew = leafSiblings[j];
          } else {
            throw new Error('Invalid node. Database corrupted');
          }
        }
      }
    } else {
      rtNew = F.zero;
      res.oldKey = key;
      res.oldValue = F.zero;
      res.isOld0 = true;
    }

    const keyQuins = this._splitQuins(key);

    for (let level = resFind.siblings.length / 4 - 1; level >= 0; level--) {
      let newSibling: ArrayLike<number>[] = [];

      if (level == resFind.siblings.length / 4 - 1 && !res.isOld0) {
        for (let j = 0; j < 4; j++) newSibling.push(F.zero);
      } else {
        newSibling = resFind.siblings.slice(4 * level, 4 * level + 4);
      }
      let oldSibling = resFind.siblings.slice(4 * level, 4 * level + 4);
      const index = keyQuins[level];

      const oldNode = oldSibling.slice();
      oldNode.splice(index, 0, rtOld);
      rtOld = getZidenParams().hasher(oldNode);

      dels.push(rtOld);
      if (
        !F.isZero(newSibling[0]) ||
        !F.isZero(newSibling[1]) ||
        !F.isZero(newSibling[2]) ||
        !F.isZero(newSibling[3])
      ) {
        mixed = true;
      }

      if (mixed) {
        for (let j = 3; j >= 0; j--) res.siblings.unshift(oldSibling[j]);
        const newNode = newSibling.slice();
        newNode.splice(index, 0, rtNew);
        rtNew = getZidenParams().hasher(newNode);
        ins.push([rtNew, newNode]);
      }
    }

    await this._db.multiIns(ins);
    await this._db.setRoot(rtNew);
    this._root = rtNew;
    await this._db.multiDel(dels);

    res.newRoot = rtNew;
    res.oldRoot = rtOld;

    return res;
  }

  /**
   * insert a new leaf into SMT, assert that the leaf is not exist in SMT
   * @param {Primitive} _key index of the inserting leaf
   * @returns {Promise<InsertingResult>} information about new root, siblings of the leaf after inserting to SMT
   */
  async insert(_key: Primitive, _value: Primitive): Promise<InsertingResult> {
    const F = getZidenParams().F;
    const key = F.e(_key);
    const value = F.e(_value);
    const keyQuins = this._splitQuins(key);
    const { ins, dels, insertingResult } = await this._addLeaf(key, value, keyQuins, this._root, 0);

    await this._db.multiIns(ins);
    await this._db.multiDel(dels);
    this._db.setRoot(insertingResult.newRoot);
    this._root = insertingResult.newRoot;

    return insertingResult;
  }

  /**
   * find a leaf with respective membership (if found) / non-membership proof (if not found) in SMT
   * @param {ArrayLike<number>} _key index of the leaf
   * @returns {Promise<FindingResult>} membership/non-membership proof
   */
  async find(_key: ArrayLike<number>): Promise<FindingResult> {
    const key = getZidenParams().F.e(_key);
    const keyQuins = this._splitQuins(key);
    return await this._find(key, keyQuins, this._root, 0);
  }

  private async _find(
    key: ArrayLike<number>,
    keyQuins: Array<number>,
    root: ArrayLike<number>,
    level: number
  ): Promise<FindingResult> {
    if (level > this._maxLevels - 1) {
      throw new Error('Reached SMT max level');
    }
    const F = getZidenParams().F;

    let res;
    if (F.isZero(root)) {
      res = {
        found: false,
        siblings: new Array<ArrayLike<number>>(),
        notFoundKey: key,
        notFoundValue: F.zero,
        isOld0: true,
      };
      return res;
    }

    const record = await this._db.get(root);
    if (!record) {
      throw new Error('Record not found in db');
    }
    // leaf record: [1, key, value]
    if (record.length == 3 && F.eq(record[0], F.one)) {
      if (F.eq(record[1], key)) {
        res = {
          found: true,
          siblings: new Array<ArrayLike<number>>(),
          foundValue: record[2],
          isOld0: false,
        };
      } else {
        res = {
          found: false,
          siblings: new Array<ArrayLike<number>>(),
          notFoundKey: record[1],
          notFoundValue: record[2],
          isOld0: false,
        };
      }
    } else {
      // internal node record: [child0, child1, child2, child3, child4]
      const index = keyQuins[level];
      res = await this._find(key, keyQuins, record[index], level + 1);
      for (let i = 4; i >= 0; i--) {
        if (i !== index) res.siblings.unshift(record[i]);
      }
    }
    return res;
  }

  private async _addLeaf(
    key: ArrayLike<number>,
    value: ArrayLike<number>,
    keyQuins: Array<number>,
    rtOld: ArrayLike<number>,
    level: number
  ): Promise<{
    ins: [ArrayLike<number>, Primitive[]][];
    dels: ArrayLike<number>[];
    insertingResult: InsertingResult;
  }> {
    const F = getZidenParams().F;
    if (level > this._maxLevels - 1) {
      throw new Error('Reached SMT max level');
    }

    // It must be in one of 3 cases:
    // - rtOld is empty node ( tree is empty ) => root = inserting leaf
    // - rtOld is a leaf =>  push leaves
    // - rtOld is an internal node => recursively call function
    if (F.isZero(rtOld)) {
      // current node is empty
      const rtNew = getZidenParams().hash1(key, value);
      return {
        ins: [[rtNew, [1, key, value]]],
        dels: [],
        insertingResult: {
          oldRoot: rtOld,
          newRoot: rtNew,
          siblings: [],
          isOld0: true,
        },
      };
    }
    const record = await this._db.get(rtOld);
    if (!record) {
      throw new Error('Record not found in db');
    }

    // current node is a leaf
    if (record.length == 3 && F.eq(record[0], F.one)) {
      // leaf record: [1, key, value]
      if (F.eq(record[1], key)) {
        throw new Error('Key already exists');
      } else {
        // push leaf
        const oldKeyIndexes = this._splitQuins(record[1]);
        const res = this._pushLeaf(record[1], oldKeyIndexes, record[2], key, keyQuins, value, level);
        const insertingResult: InsertingResult = {
          oldRoot: rtOld,
          newRoot: res.rtNew,
          oldKey: record[1],
          oldValue: record[2],
          isOld0: false,
          siblings: res.siblings,
        };
        return {
          ins: res.ins,
          dels: [],
          insertingResult,
        };
      }
    } else {
      // internal node record: [child0, child1, child2, child3, child4]
      if (record.length !== 5) {
        throw new Error(`Invalid record length, expected 5 but got ${record.length}`);
      }
      const index = keyQuins[level];
      const res = await this._addLeaf(key, value, keyQuins, record[index], level + 1);

      record[index] = res.insertingResult.newRoot;
      const rtNew = getZidenParams().hasher(record);

      res.insertingResult.newRoot = rtNew;
      res.insertingResult.oldRoot = rtOld;
      res.insertingResult.isOld0 = false;
      const siblings = record.slice();
      siblings.splice(index, 1);
      res.insertingResult.siblings.unshift(...siblings);
      res.ins.push([rtNew, record]);
      res.dels.push(rtOld);
      return res;
    }
  }

  private _pushLeaf(
    oldKey: ArrayLike<number>,
    oldKeyIndexes: number[],
    oldValue: ArrayLike<number>,
    newKey: ArrayLike<number>,
    newKeyIndexes: number[],
    newValue: ArrayLike<number>,
    level: number
  ): {
    ins: [ArrayLike<number>, Primitive[]][];
    rtNew: ArrayLike<number>;
    siblings: ArrayLike<number>[];
  } {
    if (level > this._maxLevels - 2) {
      throw new Error('Reached SMT max level');
    }
    const F = getZidenParams().F;
    if (oldKeyIndexes[level] === newKeyIndexes[level]) {
      // go deeper
      const res = this._pushLeaf(oldKey, oldKeyIndexes, oldValue, newKey, newKeyIndexes, newValue, level + 1);
      const siblings = [F.zero, F.zero, F.zero, F.zero];

      const children = siblings.slice();
      children.splice(oldKeyIndexes[level], 0, res.rtNew);
      res.rtNew = getZidenParams().hasher(children);
      res.ins.push([res.rtNew, children]);
      res.siblings.unshift(...siblings);
      return res;
    }
    const children = [];
    const oldNode = getZidenParams().hash1(oldKey, oldValue);
    const newNode = getZidenParams().hash1(newKey, newValue);
    for (let i = 0; i < 5; i++) {
      if (i === oldKeyIndexes[level]) {
        children.push(oldNode);
      } else if (i === newKeyIndexes[level]) {
        children.push(newNode);
      } else {
        children.push(F.zero);
      }
    }
    const rtNew = getZidenParams().hasher(children);
    const siblings = children.slice();
    siblings.splice(newKeyIndexes[level], 1);
    return {
      siblings,
      ins: [
        [rtNew, children],
        [getZidenParams().hash1(newKey, newValue), [1, newKey, newValue]],
      ],
      rtNew,
    };
  }
}
