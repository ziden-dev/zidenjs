import { SMTDb } from '../../db/index.js';

export type Primitive = string | number | ArrayLike<number> | BigInt;
export interface FindingResult {
  found: boolean;
  siblings: ArrayLike<number>[];
  foundValue?: ArrayLike<number>;
  notFoundKey?: ArrayLike<number>;
  notFoundValue?: ArrayLike<number>;
  isOld0: boolean;
}
export interface InsertingResult {
  oldRoot: ArrayLike<number>;
  newRoot: ArrayLike<number>;
  siblings: ArrayLike<number>[];
  oldKey?: ArrayLike<number>;
  oldValue?: ArrayLike<number>;
  isOld0: boolean;
}
export interface DeletingResult {
  oldRoot: ArrayLike<number>;
  newRoot: ArrayLike<number>;
  siblings: ArrayLike<number>[];
  oldKey?: ArrayLike<number>;
  oldValue?: ArrayLike<number>;
  delKey: ArrayLike<number>;
  delValue: ArrayLike<number>;
  isOld0: boolean;
}
export interface UpdatingResult {
  oldRoot: ArrayLike<number>;
  newRoot: ArrayLike<number>;
  siblings: ArrayLike<number>[];
  oldKey: ArrayLike<number>;
  oldValue?: ArrayLike<number>;
  newKey: ArrayLike<number>;
  newValue: ArrayLike<number>;
}

export default interface SMT {
  update(_key: Primitive, _newValue: Primitive): Promise<UpdatingResult>;
  delete(_key: Primitive): Promise<DeletingResult>;
  insert(_key: Primitive, _value: Primitive): Promise<InsertingResult>;
  find(_key: ArrayLike<number>): Promise<FindingResult>;
  readonly root: ArrayLike<number>;
  readonly db: SMTDb;
}

export { QuinSMT } from './quin-smt.js';
export { BinSMT } from './bin-smt.js';
