pragma circom 2.0.0;

include "../../circuits/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        compactInput,
                        mask]} = CredentialAtomicQueryMTP(32, 32, 10);
