pragma circom 2.1.6;
/*
include "../node_modules/circomlib/circuits/bitify.circom";
include "secp256k1_func.circom";
include "secp256k1_utils.circom";
*/

template VerifySchnorrSignature() {
    signal input a;
    signal output b;

    b <== a;
    log("just to try");
}

component main = VerifySchnorrSignature();
/* 
proof.input =  { 
   "a":3
}
*/