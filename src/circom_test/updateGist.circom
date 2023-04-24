pragma circom 2.0.0;

include "../circuits/updateGist.circom";

component main {public [oldGistRoot, oldKey, oldValue, isOld0, newKey, newValue, fnc]} = UpdateGist(64, 100);