pragma circom 2.0.0;

include "../circuits/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        claimSchema,
                        slotIndex,
                        timestamp,
                        operator,
                        mask, gistRoot]} = CredentialAtomicQueryMTP(8, 14, 64, 6);
