pragma circom 2.0.0;

include "../circuits/stateTransition.circom";

component main {public [genesisID,oldUserState,newUserState,isOldStateGenesis, gistRoot]} = StateTransition(8,64);