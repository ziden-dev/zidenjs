pragma circom 2.0.0; 
include "../../node_modules/circomlib/circuits/babyjub.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "idOwnershipBySignatureV2.circom";

include "updateGist2.circom";

template StateTransition(IdOwnershipLevels, gistLevel) {
    // we have no constraints for "id" in this circuit, however we introduce "id" input here
    // as it serves as public input which should be the same for prover and verifier
    signal input genesisID;
    signal input profileNonce;

    signal input oldUserState;
    
    signal input newUserState;
    signal input isOldStateGenesis;
	signal input userAuthsRoot;
	signal input userAuthMtp[IdOwnershipLevels * 4];
	signal input userAuthHi;
    signal input userAuthPubX;
    signal input userAuthPubY;

	signal input userClaimsRoot;
    signal input userClaimRevRoot;

	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    signal input gistRoot;
    signal input gistMtp[gistLevel];
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;

    component cutId = cutId();
    cutId.in <== genesisID;

    component cutState = cutState();
    cutState.in <== oldUserState;

    component isCutIdEqualToCutState = IsEqual();
    isCutIdEqualToCutState.in[0] <== cutId.out;
    isCutIdEqualToCutState.in[1] <== cutState.out;

    // if isOldStateGenesis != 0 then old state is genesis
    // and we must check that userID was derived from that state
    (1 - isCutIdEqualToCutState.out) * isOldStateGenesis === 0;

    // check newUserState is not zero
    component stateIsNotZero = IsZero();
    stateIsNotZero.in <== newUserState;
    stateIsNotZero.out === 0;

    // old & new state checks
    component oldNewNotEqual = IsEqual();
    oldNewNotEqual.in[0] <== oldUserState;
    oldNewNotEqual.in[1] <== newUserState;
    oldNewNotEqual.out === 0;
    
    
    // check userID ownership by correct signature of a hash of old state and new state
    component challenge = Poseidon(2);
    challenge.inputs[0] <== oldUserState;
    challenge.inputs[1] <== newUserState;

    /* Id ownership check*/
    
    component userIdOwnership = idOwnershipBySignatureV2(IdOwnershipLevels, gistLevel);

    userIdOwnership.userAuthsRoot <== userAuthsRoot;
    userIdOwnership.userAuthHi <== userAuthHi;
    userIdOwnership.userAuthPubX <== userAuthPubX;
    userIdOwnership.userAuthPubY <== userAuthPubY;
    for (var i=0; i<IdOwnershipLevels * 4; i++) { userIdOwnership.userAuthMtp[i] <== userAuthMtp[i]; }

    userIdOwnership.userClaimsRoot <== userClaimsRoot;
    userIdOwnership.userClaimRevRoot <== userClaimRevRoot;

    userIdOwnership.challenge <== challenge.out;
    userIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    userIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    userIdOwnership.challengeSignatureS <== challengeSignatureS;

    // genesis proof
    userIdOwnership.userState <== oldUserState;
    userIdOwnership.genesisID <== genesisID;
    userIdOwnership.profileNonce <== profileNonce;

    // global identity state tree on chain
    userIdOwnership.gistRoot <== gistRoot;
    // Gist proof
    for (var i = 0; i < gistLevel; i++) { userIdOwnership.gistMtp[i] <== gistMtp[i]; }
    userIdOwnership.gistMtpAuxHi <== gistMtpAuxHi;
    userIdOwnership.gistMtpAuxHv <== gistMtpAuxHv;
    userIdOwnership.gistMtpNoAux <== gistMtpNoAux;



    // new Gist proof
    signal output newGistRoot;

    component genesisIDhash = Poseidon(1);
    genesisIDhash.inputs[0] <== genesisID;

    // isStateGenesis  = 1 => Insert [ 1 / 0 ] else Update [ 0 /  1 ]
    // If sel == 0 then outL = L and outR=R
    // If sel == 1 then outL = R and outR=L
    component fncSignal = Switcher();
    fncSignal.sel <== isCutIdEqualToCutState.out;
    fncSignal.L <== 0;
    fncSignal.R <== 1;

    component processor = UpdateGistABC(gistLevel);

    processor.fnc[0] <== fncSignal.outL;
    processor.fnc[1] <== fncSignal.outR;
    //processor.fnc[0] <==0;
   //processor.fnc[1] <== 1;

    processor.oldGistRoot <== gistRoot;
    processor.oldKey <== genesisIDhash.out;
    processor.oldValue <== oldUserState;
    processor.isOld0 <== gistMtpNoAux;
    processor.newKey <== genesisIDhash.out;
    processor.newValue <== newUserState;
    
    for (var i = 0;  i < gistLevel ; i++) {
        processor.siblings[i] <== gistMtp[i];
    }
    newGistRoot <== processor.newGistRoot;
}
