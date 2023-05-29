pragma circom 2.0.0;

include "../circuits/updateGist.circom";

component main {public [oldGistRoot]} = UpdateGist(64, 1);