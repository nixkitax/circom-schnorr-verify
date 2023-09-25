pragma circom  2.1.6;

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/escalarmul.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/pointbits.circom";
include "../node_modules/circomlib/circuits/pedersen.circom";


template add(){
    signal input bitsMsg[256];

    signal output c[2];

    var base[2] = 
    [5299619240641551281634865583518297030282874472190772894086521144482721001553,
     16950150798460657717958625567821834550301663161624707787222815936182638968203];

    component pedHash = Pedersen(256);

    for( var i = 0; i < 256; i++){
        pedHash.in[i] <== bitsMsg[i];
    }

    c[0] <== pedHash.out[0];
    c[1] <== pedHash.out[1];

    log("c[0]: ", c[0], "\nc[1]: ", c[1]);
}