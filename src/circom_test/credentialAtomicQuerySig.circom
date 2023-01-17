pragma circom 2.0.0;

include "../circuits/quin/query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerAuthState,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        claimSchema,
                        slotIndex,
                        timestamp,
                        operator,
                        mask]} = CredentialAtomicQuerySig(8, 14, 6);
