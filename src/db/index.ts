export interface SMTDb{
    getRoot: () => Promise<any>;
    get: (key: any) => Promise<any>;
    multiGet: (keys: Array<any>) => Promise<any>;
    setRoot: (rt: any) => Promise<void>;
    multiIns: (inserts: any) => Promise<void>; 
    multiDel: (dels: any) => Promise<void>;
}

export {SMTLevelDb} from './level_db.js';