pragma circom 2.0.0;

include "../../../circuits/quin/query/credentialAtomicQuerySig.circom";

component main{public [challenge,
                        userID,
                        userState,
                        issuerID,
                        issuerClaimNonRevState,
                        determinisiticValue,
                        compactInput,
                        mask]} = CredentialAtomicQuerySig(14, 14, 10);
