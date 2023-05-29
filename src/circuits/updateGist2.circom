pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/smt/smtprocessor.circom";

template UpdateGistABC(gistLevel){
    signal input oldGistRoot;

    signal input siblings[gistLevel];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;
    signal input newKey;
    signal input newValue;
    signal input fnc[2];

    log(" signal = ", fnc[0], fnc[1]);
    log(" oldGistRoot = ", oldGistRoot);
    log(" oldKey = ", oldKey);
    log(" oldValue = ", oldValue);
    log(" isOld = ", isOld0);
    log(" newKey = ", newKey);
    log(" newValue = ", newValue);
    signal output newGistRoot;

    component processor = SMTProcessor(gistLevel);

    processor.oldRoot <== oldGistRoot;

    for(var i = 0; i < gistLevel; i++){
        processor.siblings[i] <== siblings[i];
    }
    processor.oldKey <== oldKey;
    processor.oldValue <== oldValue;
    processor.isOld0 <== isOld0;
    processor.newKey <== newKey;
    processor.newValue <== newValue;
    processor.fnc[0] <== fnc[0];
    processor.fnc[1] <== fnc[1];
    log(" New Gist Root = ", processor.newRoot);
    newGistRoot <== processor.newRoot;
}