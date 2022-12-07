pragma circom 2.0.0;

include "../../../circuits/bin/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimIdenState,
                        determinisiticValue,
                        compactInput,
                        mask]} = CredentialAtomicQueryMTP(8, 32, 10);
