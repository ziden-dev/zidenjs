pragma circom 2.0.0;

include "idOwnershipBySignature.circom";

template VerifyAuthentication(IdOwnershipLevels) {

	signal input userAuthTreeRoot;
	signal input userAuthClaimMtp[IdOwnershipLevels];
	signal input userAuthClaim[8];

	signal input userClaimsTreeRoot;
    signal output authClaimRevocationNonce;
    
	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;
	
    signal input userState;
    // we have no constraints for "id" in this circuit, however we introduce "id" input here
    // as it serves as public input which should be the same for prover and verifier
    signal input userID;

    component checkIdOwnership = IdOwnershipBySignature(IdOwnershipLevels);

	checkIdOwnership.userAuthTreeRoot <== userAuthTreeRoot;
	for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.userAuthClaimMtp[i] <== userAuthClaimMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.userAuthClaim[i] <== userAuthClaim[i]; }

    checkIdOwnership.userClaimsTreeRoot <== userClaimsTreeRoot;

    checkIdOwnership.challenge <== challenge;
    checkIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== challengeSignatureS;
    
    checkIdOwnership.userState <== userState;

    authClaimRevocationNonce <== checkIdOwnership.authClaimRevocationNonce;
}
