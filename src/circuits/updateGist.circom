pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/smt/smtprocessor.circom";

template UpdateGist(gistLevel, numberOfLeaves){
    signal input oldGistRoot;
    signal output newGistRoot;

    signal input siblings[gistLevel * numberOfLeaves];
    signal input oldKey[numberOfLeaves];
    signal input oldValue[numberOfLeaves];
    signal input isOld0[numberOfLeaves];
    signal input newKey[numberOfLeaves];
    signal input newValue[numberOfLeaves];
    signal input fnc[2 * numberOfLeaves];

    component processor[numberOfLeaves];
    for(var i = 0; i < numberOfLeaves; i++){
        processor[i] = SMTProcessor(gistLevel);

        if(i == 0){
            processor[i].oldRoot <== oldGistRoot;
        }
        else {
            processor[i].oldRoot <== processor[i - 1].newRoot;
        }
        
        for(var j = 0; j < gistLevel; j++){
            processor[i].siblings[j] <== siblings[i * gistLevel + j];
        }

        processor[i].oldKey <== oldKey[i];
        processor[i].oldValue <== oldValue[i];
        processor[i].isOld0 <== isOld0[i];
        processor[i].newKey <== newKey[i];
        processor[i].newValue <== newValue[i];
        processor[i].fnc[0] <== fnc[i * 2];
        processor[i].fnc[1] <== fnc[i * 2 + 1];
    }

    newGistRoot <== processor[numberOfLeaves - 1].newRoot;
}