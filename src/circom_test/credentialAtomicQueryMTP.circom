pragma circom 2.0.0;

include "../circuits/quin/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        claimSchema,
                        slotIndex,
                        timestamp,
                        operator,
                        mask]} = CredentialAtomicQueryMTP(8, 14, 6);
