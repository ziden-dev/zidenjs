pragma circom 2.0.0;

include "lib/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQueryMTP(32, 32, 10);

// timestamp 64 bits
// claim schema 128 bits
// slotIndex 3 bits
// operator 3 bits
// => compress to 1 input => 8 public inputs