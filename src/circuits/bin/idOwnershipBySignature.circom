/*
# idOwnershipBySignature.circom

Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
*/

pragma circom 2.0.0;

include "utils/claimUtils.circom";
include "utils/treeUtils.circom";

template IdOwnershipBySignature(nLevels) {
    signal input userState;

	signal input userAuthTreeRoot;
	signal input userAuthClaimMtp[nLevels];
	signal input userAuthClaim[8];

	signal input userClaimsTreeRoot;
    signal output authClaimRevocationNonce;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;


    component verifyAuthClaim = VerifyAuthClaimAndSignature(nLevels);
    for (var i=0; i<8; i++) { verifyAuthClaim.authClaim[i] <== userAuthClaim[i]; }
	for (var i=0; i<nLevels; i++) { verifyAuthClaim.authClaimMtp[i] <== userAuthClaimMtp[i]; }
	verifyAuthClaim.authTreeRoot <== userAuthTreeRoot;

    verifyAuthClaim.challengeSignatureS <== challengeSignatureS;
    verifyAuthClaim.challengeSignatureR8x <== challengeSignatureR8x;
    verifyAuthClaim.challengeSignatureR8y <== challengeSignatureR8y;
    verifyAuthClaim.challenge <== challenge;

    component checkUserState = checkIdenStateMatchesRoots();
    checkUserState.claimsTreeRoot <== userClaimsTreeRoot;
    checkUserState.authTreeRoot <== userAuthTreeRoot;

    checkUserState.expectedState <== userState;

    component getRevNonce = getClaimRevNonce();
    getRevNonce.slot <== userAuthClaim[4];
    authClaimRevocationNonce <== getRevNonce.revNonce;
}

