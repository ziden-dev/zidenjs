// @ts-ignore
import { Scalar } from 'ffjavascript';
import { Hash1, Hasher, SnarkField } from '../global.js';
import { SMTDb } from '../db/index.js';
import { assert } from 'console';

export type Primitive = string | number | ArrayLike<number> | BigInt;
interface FindingResult {
  found: boolean;
  siblings: ArrayLike<number>[];
  foundValue?: ArrayLike<number>;
  notFoundKey?: ArrayLike<number>;
  notFoundValue?: ArrayLike<number>;
  isOld0: boolean;
}
interface InsertingResult {
  oldRoot: ArrayLike<number>;
  newRoot: ArrayLike<number>;
  siblings: ArrayLike<number>[];
  oldKey?: ArrayLike<number>;
  oldValue?: ArrayLike<number>;
  isOld0: boolean;
}
interface DeletingResult {
  oldRoot: ArrayLike<number>;
  newRoot: ArrayLike<number>;
  siblings: ArrayLike<number>[];
  oldKey?: ArrayLike<number>;
  oldValue?: ArrayLike<number>;
  delKey: ArrayLike<number>;
  delValue: ArrayLike<number>;
  isOld0: boolean;
}
interface UpdatingResult {
  oldRoot: ArrayLike<number>;
  newRoot: ArrayLike<number>;
  siblings: ArrayLike<number>[];
  oldKey: ArrayLike<number>;
  oldValue?: ArrayLike<number>;
  newKey: ArrayLike<number>;
  newValue: ArrayLike<number>;
}

export class QuinSMT {
  private _db: SMTDb;
  private _root: ArrayLike<number>;
  private _hasher: Hasher;
  private _hash1: Hash1;
  private _F: SnarkField;
  private _maxLevels: number;
  constructor(db: SMTDb, root: ArrayLike<number>, hasher: Hasher, hash1: Hash1, F: SnarkField, maxLevels: number) {
    this._db = db;
    this._root = root;
    this._hasher = hasher;
    this._hash1 = hash1;
    this._F = F;
    this._maxLevels = maxLevels;
  }

  get db(): SMTDb {
    return this._db;
  }
  get root(): ArrayLike<number> {
    return this._root;
  }
  get hasher(): Hasher {
    return this._hasher;
  }
  get hash1(): Hash1 {
    return this._hash1;
  }
  get F(): SnarkField {
    return this._F;
  }

  // key structure: list of tuple of 3 big-endian bits, from the root the leaf.
  private _splitBits(_key: ArrayLike<number>): Array<number> {
    const F = this._F;
    const res = Scalar.bits(F.toObject(_key));

    while (res.length < this._maxLevels * 3) res.push(0);

    return res;
  }

  /**
   * update a leaf of SMT, if the leaf with oldValue is not exist, insert the leaf into SMT
   * @param {Primitive} _key index of the updating leaf
   * @param {Primitive} _newValue new value of the updating leaf
   * @returns {Promise<UpdatingResult>} information about new root, siblings of the leaf after updating
   */
  async update(_key: Primitive, _newValue: Primitive): Promise<UpdatingResult> {
    const F = this._F;
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

    let rtOld = this._hash1(key, resFind.foundValue!);
    let rtNew = this._hash1(key, newValue);
    ins.push([rtNew, [1, key, newValue]]);
    dels.push(rtOld);

    const keyBits = this._splitBits(key);
    for (let level = resFind.siblings.length / 4 - 1; level >= 0; level--) {
      const index = 4 * keyBits[3 * level] + 2 * keyBits[3 * level + 1] + keyBits[3 * level + 2];

      const oldNode = resFind.siblings.slice(4 * level, 4 * level + 4)
      oldNode.splice(index, 0, rtOld);
      const newNode = resFind.siblings.slice(4 * level, 4 * level + 4)
      newNode.splice(index, 0, rtNew);
      rtOld = this._hasher(oldNode);
      rtNew = this._hasher(newNode);
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
    const F = this._F;
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
    let rtOld = this._hash1(key, resFind.foundValue!);
    let rtNew;
    dels.push(rtOld);

    let mixed;
    if (resFind.siblings.length > 0) {
      const record = await this._db.get(resFind.siblings[resFind.siblings.length - 1]);
      if (!record) {
        throw new Error('Record not found in db');
      }
      if (record.length == 3 && F.eq(record[0], F.one)) {
        mixed = false;
        res.oldKey = record[1];
        res.oldValue = record[2];
        res.isOld0 = false;
        rtNew = resFind.siblings[resFind.siblings.length - 1];
      } else if (record.length == 2) {
        mixed = true;
        res.oldKey = key;
        res.oldValue = F.zero;
        res.isOld0 = true;
        rtNew = F.zero;
      } else {
        throw new Error('Invalid node. Database corrupted');
      }
    } else {
      rtNew = F.zero;
      res.oldKey = key;
      res.oldValue = F.zero;
      res.isOld0 = true;
    }

    const keyBits = this._splitBits(key);

    for (let level = resFind.siblings.length / 4 - 1; level >= 0; level--) {
      let newSibling: ArrayLike<number>[] = [];

      if (level == resFind.siblings.length / 4 - 1 && !res.isOld0) {
        for (let j = 0; j < 4; j++) newSibling.push(F.zero);
      } else {
        newSibling = resFind.siblings.slice(4 * level, 4 * level + 4);
      }
      let oldSibling = resFind.siblings.slice(4 * level, 4 * level + 4);
      const index = 4 * keyBits[3 * level] + 2 * keyBits[3 * level + 1] + keyBits[3 * level + 2];

      const oldNode = oldSibling.slice();
      oldNode.splice(index, 0, rtOld);
      rtOld = this._hasher(oldNode);

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
        rtNew = this._hasher(newNode);
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
    const F = this._F;
    const key = F.e(_key);
    const value = F.e(_value);
    let addedOne = false;
    let res: InsertingResult = {
      oldRoot: this._root,
      siblings: [],
      newRoot: F.zero,
      isOld0: true,
    };
    const newKeyBits = this._splitBits(key);

    let rtOld: ArrayLike<number> = F.zero;
    
    const t = Date.now();
    const resFind = await this.find(key);
    console.log("find time: ", Date.now() - t);
    if (resFind.found) throw new Error('Key already exists');

    assert(resFind.siblings.length % 4 === 0, 'Invalid sibling list');

    res.siblings = resFind.siblings;

    let mixed;

    if (!resFind.isOld0) {
      let i;
      const oldKeyBits = this._splitBits(resFind.notFoundKey!);
      for (
        i = res.siblings.length / 4;
        oldKeyBits[3 * i] === newKeyBits[3 * i] &&
        oldKeyBits[3 * i + 1] === newKeyBits[3 * i + 1] &&
        oldKeyBits[3 * i + 2] === newKeyBits[3 * i + 2];
        i++
      ) {
        for (let j = 0; j < 4; j++) res.siblings.push(F.zero);
        if (i === this._maxLevels - 1) {
          throw new Error('Reached SMT max level');
        }
      }
      const offset = 3 * i;
      const oldIndex = 4 * oldKeyBits[offset] + 2 * oldKeyBits[offset + 1] + oldKeyBits[offset + 2];
      const newIndex = 4 * newKeyBits[offset] + 2 * newKeyBits[offset + 1] + newKeyBits[offset + 2];

      rtOld = this._hash1(resFind.notFoundKey!, resFind.notFoundValue!);
      for (let j = 0; j < 5; j++) {
        if (j === oldIndex) res.siblings.push(rtOld);
        else if (j !== newIndex) res.siblings.push(F.zero);
      }
      addedOne = true;
      mixed = false;
    } else if (res.siblings.length > 0) {
      mixed = true;
      rtOld = F.zero;
    }

    const ins: [ArrayLike<number>, Primitive[]][] = [];
    const dels: ArrayLike<number>[] = [];

    let rt = this._hash1(key, value);
    ins.push([rt, [1, key, value]]);

    for (let i = res.siblings.length / 4 - 1; i >= 0; i--) {
      if (
        i < res.siblings.length / 4 - 1 &&
        (!F.isZero(res.siblings[4 * i]) ||
          !F.isZero(res.siblings[4 * i + 1]) ||
          !F.isZero(res.siblings[4 * i + 2]) ||
          !F.isZero(res.siblings[4 * i + 3]))
      ) {
        mixed = true;
      }
      const newIndex = 4 * newKeyBits[3 * i] + 2 * newKeyBits[3 * i + 1] + newKeyBits[3 * i + 2];
      if (mixed) {
        const oldNode = res.siblings.slice(4 * i, 4 * i + 4);
        oldNode.splice(newIndex, 0, rtOld)
        rtOld = this._hasher(oldNode);
        dels.push(rtOld);
      }

      const newNode = res.siblings.slice(4 * i, 4 * i + 4);
      newNode.splice(newIndex, 0, rt);
      let rtNew = this._hasher(newNode);
      ins.push([rtNew, res.siblings.slice(4 * i, 4 * i + 4)]);
      rt = rtNew;
    }

    if (addedOne) for (let j = 0; j < 4; j++) res.siblings.pop();
    while (
      res.siblings.length >= 4 &&
      F.isZero(res.siblings[res.siblings.length - 1]) &&
      F.isZero(res.siblings[res.siblings.length - 2]) &&
      F.isZero(res.siblings[res.siblings.length - 3]) &&
      F.isZero(res.siblings[res.siblings.length - 4])
    ) {
      for (let j = 0; j < 4; j++) res.siblings.pop();
    }
    res.oldKey = resFind.notFoundKey;
    res.oldValue = resFind.notFoundValue;
    res.newRoot = rt;
    res.isOld0 = resFind.isOld0;

    const t1 = Date.now();
    await this._db.multiIns(ins);
    await this._db.setRoot(rt);
    this._root = rt;
    await this._db.multiDel(dels);
    console.log("Update db time: ", Date.now() - t1);
    return res;
  }

  /**
   * find a leaf with respective membership (if found) / non-membership proof (if not found) in SMT
   * @param {ArrayLike<number>} _key index of the leaf
   * @returns {Promise<FindingResult>} membership/non-membership proof
   */
  async find(_key: ArrayLike<number>): Promise<FindingResult> {
    const key = this._F.e(_key);
    const keyBits = this._splitBits(key);
    return await this._find(key, keyBits, this._root, 0);
  }

  async _find(
    key: ArrayLike<number>,
    keyBits: Array<number>,
    root: ArrayLike<number>,
    level: number
  ): Promise<FindingResult> {
    if (level > this._maxLevels - 1) {
      throw new Error('Reached SMT max level');
    }
    const F = this._F;

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
      const offset = 3 * level;
      const index = 4 * keyBits[offset] + 2 * keyBits[offset + 1] + keyBits[offset + 2];
      assert(index < 5, 'invalid key');

      res = await this._find(key, keyBits, record[index], level + 1);
      for (let i = 5; i >= 0; i--) {
        if (i !== index) res.siblings.unshift(record[i]);
      }
    }
    return res;
  }
}
