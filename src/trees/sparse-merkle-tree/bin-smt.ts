// @ts-ignore
import { Scalar } from 'ffjavascript';
import { Hash0, Hash1, SnarkField } from '../../global.js';
import { SMTDb } from '../../db/index.js';
import SMT, { DeletingResult, FindingResult, InsertingResult, Primitive, UpdatingResult } from './index.js';

export class BinSMT implements SMT {
  _db: SMTDb;
  _root: ArrayLike<number>;
  _hash0: Hash0;
  _hash1: Hash1;
  _F: SnarkField;
  _maxLevels: number;
  constructor(db: SMTDb, root: ArrayLike<number>, hash0: Hash0, hash1: Hash1, F: SnarkField, maxLevels: number) {
    this._db = db;
    this._root = root;
    this._hash0 = hash0;
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
  get hash0(): Hash0 {
    return this._hash0;
  }
  get hash1(): Hash1 {
    return this._hash1;
  }
  get F(): SnarkField {
    return this._F;
  }

  private _splitBits(_key: ArrayLike<number>): Array<number> {
    const F = this._F;
    const res = Scalar.bits(F.toObject(_key));

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
    for (let level = resFind.siblings.length - 1; level >= 0; level--) {
      let oldNode, newNode;
      const sibling = resFind.siblings[level];
      if (keyBits[level]) {
        oldNode = [sibling, rtOld];
        newNode = [sibling, rtNew];
      } else {
        oldNode = [rtOld, sibling];
        newNode = [rtNew, sibling];
      }
      rtOld = this._hash0(oldNode[0], oldNode[1]);
      rtNew = this._hash0(newNode[0], newNode[1]);
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

    for (let level = resFind.siblings.length - 1; level >= 0; level--) {
      let newSibling = resFind.siblings[level];
      if (level == resFind.siblings.length - 1 && !res.isOld0) {
        newSibling = F.zero;
      }
      const oldSibling = resFind.siblings[level];
      if (keyBits[level]) {
        rtOld = this._hash0(oldSibling, rtOld);
      } else {
        rtOld = this._hash0(rtOld, oldSibling);
      }
      dels.push(rtOld);
      if (!F.isZero(newSibling)) {
        mixed = true;
      }

      if (mixed) {
        res.siblings.unshift(resFind.siblings[level]);
        let newNode;
        if (keyBits[level]) {
          newNode = [newSibling, rtNew];
        } else {
          newNode = [rtNew, newSibling];
        }
        rtNew = this._hash0(newNode[0], newNode[1]);
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

    const resFind = await this.find(key);

    if (resFind.found) throw new Error('Key already exists');

    res.siblings = resFind.siblings;
    let mixed;

    if (!resFind.isOld0) {
      const oldKeyBits = this._splitBits(resFind.notFoundKey!);
      for (let i = res.siblings.length; oldKeyBits[i] === newKeyBits[i]; i++) {
        res.siblings.push(F.zero);
        if(i === this._maxLevels - 1){
            throw new Error('Reached SMT max level')
        }
      }
      rtOld = this._hash1(resFind.notFoundKey!, resFind.notFoundValue!);
      res.siblings.push(rtOld);
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

    for (let i = res.siblings.length - 1; i >= 0; i--) {
      if (i < res.siblings.length - 1 && !F.isZero(res.siblings[i])) {
        mixed = true;
      }
      if (mixed) {
        const oldSibling = resFind.siblings[i];
        if (newKeyBits[i]) {
          rtOld = this._hash0(oldSibling, rtOld);
        } else {
          rtOld = this._hash0(rtOld, oldSibling);
        }
        dels.push(rtOld);
      }

      let newRt;
      if (newKeyBits[i]) {
        newRt = this._hash0(res.siblings[i], rt);
        ins.push([newRt, [res.siblings[i], rt]]);
      } else {
        newRt = this._hash0(rt, res.siblings[i]);
        ins.push([newRt, [rt, res.siblings[i]]]);
      }
      rt = newRt;
    }

    if (addedOne) res.siblings.pop();
    while (res.siblings.length > 0 && F.isZero(res.siblings[res.siblings.length - 1])) {
      res.siblings.pop();
    }
    res.oldKey = resFind.notFoundKey;
    res.oldValue = resFind.notFoundValue;
    res.newRoot = rt;
    res.isOld0 = resFind.isOld0;

    await this._db.multiIns(ins);
    await this._db.setRoot(rt);
    this._root = rt;
    await this._db.multiDel(dels);

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

  private async _find(
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
      if (keyBits[level] === 0) {
        res = await this._find(key, keyBits, record[0], level + 1);
        res.siblings.unshift(record[1]);
      } else {
        res = await this._find(key, keyBits, record[1], level + 1);
        res.siblings.unshift(record[0]);
      }
    }
    return res;
  }
}
