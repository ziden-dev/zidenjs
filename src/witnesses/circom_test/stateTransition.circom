pragma circom 2.0.0;

include "../../circuits/stateTransition.circom";

component main {public [userID,oldUserState,newUserState,isOldStateGenesis]} = StateTransition(32);