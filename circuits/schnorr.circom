pragma circom 2.1.6;

include "compconstant.circom";
include "pointbits.circom";


template verifySchnorrSignature(n) {
    
    var G[2] = [
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        ];

    signal input msg[n];
    signal input Lsign[32]; // R : L_Sign
    signal input Rsign[32]; // S : R_Sign
    signal input pubKey;    // pubKey


    signal e; // H(R || P || msg)

    //TODO: check g^s + P ^ (-e) == R ?? ==> 
    // G ^ R_Sign + pubKey ^ (-e ) == L_Sign ???

    



}

component main = verifySchnorrSignature();

