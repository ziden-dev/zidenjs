pragma circom 2.0.0;

include "../../circuits/query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        compactInput,
                        mask]} = CredentialAtomicQuerySig(32, 32, 10);
