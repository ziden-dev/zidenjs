import { Level } from 'level';
import { Primitive } from '../state/sparse-merkle-tree/index.js';
import { getZidenParams } from '../global.js';
import { SMTDb } from './index.js';

export class SMTLevelDb implements SMTDb {
  private _nodes: Level<string, string>;
  constructor(pathDb: string) {
    this._nodes = new Level(pathDb);
  }

  get nodes(){
    return this._nodes
  }
  
  async getRoot() {
    try {
      const rootS = await this._nodes.get('root');
      if (rootS) return getZidenParams().F.e(BigInt(rootS));
    } catch (err) {}
    return getZidenParams().F.zero;
  }

  _key2str(k: ArrayLike<number>) {
    const keyS = getZidenParams().F.toString(k);
    return keyS;
  }

  _normalize(n: Primitive[]): Array<ArrayLike<number>> {
    const result: Array<ArrayLike<number>> = [];
    for (let i = 0; i < n.length; i++) {
      result.push(getZidenParams().F.e(n[i]));
    }
    return result;
  }
  /**
   * Convert to string
   * normally used in order to add it to database
   * @param {Array<ArrayLike<number>>} val - any input parameter
   * @returns {String}
   */
  _serialize(val: ArrayLike<number>[]): string {
    return JSON.stringify(val.map((e) => getZidenParams().F.toObject(e).toString()));
  }

  /**
   * Get from string
   * normally used ti get from database
   * @param {String} val - string to parse
   * @returns {Array<ArrayLike<number>>}
   */
  _deserialize(val: string): Array<ArrayLike<number>> {
    return JSON.parse(val).map((v: string) => getZidenParams().F.e(BigInt(v)));
  }

  async get(key: ArrayLike<number>) {
    const keyS = this._key2str(key);
    const valueS = await this._nodes.get(keyS);
    if (valueS) {
      const value = this._deserialize(valueS);
      return value;
    }
    return undefined;
  }

  async multiGet(keys: ArrayLike<number>[]) {
    const promises = [];
    for (let i = 0; i < keys.length; i++) {
      promises.push(this.get(keys[i]));
    }
    return await Promise.all(promises);
  }

  async setRoot(rt: ArrayLike<number>) {
    await this._nodes.put('root', getZidenParams().F.toObject(rt).toString());
  }

  async multiIns(inserts: [ArrayLike<number>, Primitive[]][]) {
    const works = [];
    for (let i = 0; i < inserts.length; i++) {
      const keyS = this._key2str(inserts[i][0]);
      const normolized = this._normalize(inserts[i][1]);
      const valueS = this._serialize(normolized);
      works.push({ type: 'put', key: keyS, value: valueS });
    }
    // @ts-ignore
    await this._nodes.batch(works);
  }

  async multiDel(dels: ArrayLike<number>[]) {
    const works = [];
    for (let i = 0; i < dels.length; i++) {
      const keyS = this._key2str(dels[i]);
      works.push({ type: 'del', key: keyS });
    }
    // @ts-ignore
    await this._nodes.batch(works);
  }
}
