/*
# idOwnershipBySignature.circom

Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
*/

pragma circom 2.0.0;

include "utils/claimUtils.circom";
include "utils/treeUtils.circom";
include "utils/idUtils.circom";
include "quinarySmt/quinSmtVerifier.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/smt/smtverifier.circom";


template idOwnershipBySignatureV2(nLevels, gistLevel) {
    signal output userID;
    signal input genesisID;
    signal input profileNonce;

    signal input userState;

	signal input userAuthsRoot;
	signal input userAuthMtp[nLevels * 4];
	signal input userAuthHi;
    signal input userAuthPubX;
    signal input userAuthPubY;

	signal input userClaimsRoot;
    signal input userClaimRevRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    signal input gistRoot;
    signal input gistMtp[gistLevel];
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;


    component verifyAuth = VerifyAuthAndSignature(nLevels);
    
    verifyAuth.authHi <== userAuthHi;
    verifyAuth.authPubX <== userAuthPubX;
    verifyAuth.authPubY <== userAuthPubY;
	for (var i=0; i<nLevels * 4; i++) { verifyAuth.authMtp[i] <== userAuthMtp[i]; }
	verifyAuth.authsRoot <== userAuthsRoot;

    verifyAuth.challengeSignatureS <== challengeSignatureS;
    verifyAuth.challengeSignatureR8x <== challengeSignatureR8x;
    verifyAuth.challengeSignatureR8y <== challengeSignatureR8y;
    verifyAuth.challenge <== challenge;

    component checkUserState = checkIdenStateMatchesRoots();
    checkUserState.authsRoot <== userAuthsRoot;
    checkUserState.claimsRoot <== userClaimsRoot;
    checkUserState.claimRevRoot <== userClaimRevRoot;
    checkUserState.expectedState <== userState;

    component cutId = cutId();
    cutId.in <== genesisID;

    component cutState = cutState();
    cutState.in <== userState;

    component isStateGenesis = IsEqual();
    isStateGenesis.in[0] <== cutId.out;
    isStateGenesis.in[1] <== cutState.out;

    component genesisIDhash = Poseidon(1);
    genesisIDhash.inputs[0] <== genesisID;

    component gistCheck = SMTVerifier(gistLevel);
    gistCheck.enabled <== 1;
    gistCheck.fnc <== isStateGenesis.out; // non-inclusion in case if genesis state, otherwise inclusion
	gistCheck.root <== gistRoot;
	for (var i=0; i<gistLevel; i++) { gistCheck.siblings[i] <== gistMtp[i]; }
	gistCheck.oldKey <== gistMtpAuxHi;
	gistCheck.oldValue <== gistMtpAuxHv;
	gistCheck.isOld0 <== gistMtpNoAux;
	gistCheck.key <== genesisIDhash.out;
	gistCheck.value <== userState;

    /* ProfileID calculation */
    component calcProfile = SelectProfile();
    calcProfile.in <== genesisID;
    calcProfile.nonce <== profileNonce;

    userID <== calcProfile.out;
}

