pragma circom 2.0.0;

include "../circuits/quin/stateTransition.circom";

component main {public [userID,oldUserState,newUserState,isOldStateGenesis]} = StateTransition(8);