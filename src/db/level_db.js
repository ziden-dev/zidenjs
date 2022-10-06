import { Level } from "level";

export class SMTLevelDb {
  constructor(pathDb, F) {
    this.nodes = new Level(pathDb);
    this.F = F;
  }

  async getRoot() {
    try {
      const rootS = await this.nodes.get("root");
      if (rootS) return this.F.e(BigInt(rootS));
    } catch (err) {}
    return this.F.zero;
  }

  _key2str(k) {
    const F = this.F;
    const keyS = this.F.toString(k);
    return keyS;
  }

  _normalize(n) {
    const F = this.F;
    for (let i = 0; i < n.length; i++) {
      n[i] = this.F.e(n[i]);
    }
  }
  /**
   * Convert to string
   * normally used in order to add it to database
   * @param {Any} - any input parameter
   * @returns {String}
   */
  _serialize(val) {
    return JSON.stringify(val.map((e) => this.F.toObject(e).toString()));
  }

  /**
   * Get from string
   * normally used ti get from database
   * @param {String} - string to parse
   * @returns {Any}
   */
  _deserialize(val) {
    return JSON.parse(val).map((v) => this.F.e(BigInt(v)));
  }
  async get(key) {
    const keyS = this._key2str(key);
    const valueS = await this.nodes.get(keyS);
    if (valueS) {
      const value = this._deserialize(valueS);
      return value;
    }
    return undefined;
  }

  async multiGet(keys) {
    const promises = [];
    for (let i = 0; i < keys.length; i++) {
      promises.push(this.get(keys[i]));
    }
    return await Promise.all(promises);
  }

  async setRoot(rt) {
    await this.nodes.put("root", this.F.toObject(rt).toString());
  }

  async multiIns(inserts) {
    for (let i = 0; i < inserts.length; i++) {
      const keyS = this._key2str(inserts[i][0]);
      this._normalize(inserts[i][1]);
      const valueS = this._serialize(inserts[i][1]);
      await this.nodes.put(keyS, valueS);
    }
  }

  async multiDel(dels) {
    for (let i = 0; i < dels.length; i++) {
      const keyS = this._key2str(dels[i]);
      await this.nodes.del(keyS);
    }
  }
}
