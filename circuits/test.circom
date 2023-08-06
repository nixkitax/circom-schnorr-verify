pragma circom 2.1.6;

include "./circomlib/circuits/sha256/sha256.circom";

template hashing(){
    signal input in[6];
    signal output out[256];

    component SHA = Sha256(6);
    SHA.in <== in;
    out <== SHA.out;
}

component main = hashing();
