pragma circom 2.1.6;

include "compconstant.circom";
include "pointbits.circom";


template verifySchnorrSignature(n) {
    
    signal input msg[n];
    signal input Lsign[32];
    signal input Rsign[32];
    signal input pubKey;
    

    var BASEPOINT[2] = [
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    ];

    //g (BASEPOINT) := base point -> non il generatore 
    //s (sign) := presa dalla signature 
    //y := publicKey
    //r_v := g^s * y^e
    //e_v := H_poseidon(r_v || msg)

    //if e == e_v true else false



}

component main = verifySchnorrSignature();

