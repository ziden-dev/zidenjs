pragma circom 2.0.0;

include "../../circuits/quin/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        compactInput,
                        mask]} = CredentialAtomicQueryMTP(14, 14, 10);
