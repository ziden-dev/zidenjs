import { Primitive } from '../trees/sparse-merkle-tree/index.js';

export interface SMTDb{
    getRoot(): Promise<ArrayLike<number>>;
    get(key: ArrayLike<number>): Promise<ArrayLike<number>[] | undefined>;
    multiGet(keys: Array<ArrayLike<number>>): Promise<(ArrayLike<number>[] | undefined)[]>;
    setRoot: (rt: ArrayLike<number>) => Promise<void>;
    multiIns: (inserts: ([ArrayLike<number>, Primitive[]])[]) => Promise<void>; 
    multiDel: (dels: ArrayLike<number>[]) => Promise<void>;
}

export {SMTLevelDb} from './level_db.js';