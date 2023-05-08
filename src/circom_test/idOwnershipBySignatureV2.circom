pragma circom 2.0.0;

include "../circuits/idOwnershipBySignatureV2.circom";

component main { public [gistRoot]} = idOwnershipBySignatureV2(8, 64);