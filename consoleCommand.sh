#!/bin/bash

circom src/circom_test/credentialAtomicQueryMTP.circom --r1cs --wasm --sym -o buildCircom

snarkjs groth16 setup buildCircom/credentialAtomicQueryMTP.r1cs pot15_final.ptau buildCircom/credentialAtomicQueryMTP_0000.zkey 

snarkjs zkey contribute buildCircom/credentialAtomicQueryMTP_0000.zkey buildCircom/credentialAtomicQueryMTP_0001.zkey --name="1st Contributor Name" -v 

snarkjs zkey beacon buildCircom/credentialAtomicQueryMTP_0001.zkey buildCircom/credentialAtomicQueryMTP.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2" 

snarkjs zkey verify buildCircom/credentialAtomicQueryMTP.r1cs pot15_final.ptau buildCircom/credentialAtomicQueryMTP.zkey 

snarkjs zkesv buildCircom/credentialAtomicQueryMTP.zkey buildCircom/credentialAtomicQueryMTP.sol 

circom src/circom_test/stateTransition.circom --r1cs --wasm --sym -o buildCircom

snarkjs groth16 setup buildCircom/stateTransition.r1cs pot15_final.ptau buildCircom/stateTransition_0000.zkey 

snarkjs zkey contribute buildCircom/stateTransition_0000.zkey buildCircom/stateTransition_0001.zkey --name="1st Contributor Name" -v 

snarkjs zkey beacon buildCircom/stateTransition_0001.zkey buildCircom/stateTransition.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2" 

snarkjs zkey verify buildCircom/stateTransition.r1cs pot15_final.ptau buildCircom/stateTransition.zkey 

snarkjs zkesv buildCircom/stateTransition.zkey buildCircom/stateTransition.sol 

