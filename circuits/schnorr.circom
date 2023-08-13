pragma circom 2.1.6;

include "compconstant.circom";
include "pointbits.circom";


template verifySchnorrSignature(n) {
    
    signal input msg[n];

    
    

    signal input 

    var BASEPOINT[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    //g := base point -> non il generatore 
    //s := presa dalla signature 
    //y := publicKey
    //r_v := g^s * y^e
    //e_v := H_poseidon(r_v || msg)

    //if e == e_v true else false



}

component main = verifySchnorrSignature();

