pragma circom 2.0.0;

include "../../../circuits/bin/query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        determinisiticValue,
                        compactInput,
                        issuerState,
                        mask]} = CredentialAtomicQuerySig(8, 8, 10);
