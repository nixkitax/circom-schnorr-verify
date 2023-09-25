pragma circom 2.1.6;

include "./circomlib/circuits/bitify.circom";
include "./circomlib/circuits/babyjub.circom";
include "./circomlib/circuits/pedersen.circom";
include "./circomlib/circuits/sha256/sha256.circom";
include "./circomlib/circuits/pointbits.circom";
include "./circomlib/circuits/escalarmulfix.circom";


template verifyKey(nBits){
  
    signal input Rx[256];
    signal input s[256];
    signal input e[256];
    signal input pPub[256];
    signal input msg[nBits];

    signal pPubx;
    signal pPuby;

    var BASE8[2] = [
      5299619240641551281634865583518297030282874472190772894086521144482721001553,
      16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    var order = 21888242871839275222246405745257275088614511777268538073601725287587578984328;
    var i;
    component bits2pointpPub = Bits2Point_Strict();

    for (i=0; i<256; i++) {
        bits2pointpPub.in[i] <== pPub[i];
    }
    pPubx <== bits2pointpPub.out[0];
    pPuby <== bits2pointpPub.out[1];


  // Calculate the h = H(R,A, msg)

    component hash = Pedersen(512+nBits);

    for (i=0; i<256; i++) {
        hash.in[i] <== Rx[i];
        hash.in[256+i] <== pPub[i];
    }
    for (i=0; i< nBits; i++) {
        hash.in[512+i] <== msg[i];
    }


    component point2bitsH = Point2Bits_Strict();
    point2bitsH.in[0] <== hash.out[0];
    point2bitsH.in[1] <== hash.out[1];

    
    point2bitsH.out 
    //TODO: Calculate e = BigInt(hash.out) % order

    
    //Calculate gs and Pe

    component gs = EscalarMulFix(256, BASE8);
    
    for (var i=0; i<256; i++) {
        gs.e[i] <== s[i];
    }

    component Pe = EscalarMulFix(256, BASE8);

    //TODO: order - e => signal

    for (var i=0; i<256; i++) {
          Pe.e[i] <== s[i];
    }

    log("gs ", gs.out[0], " ", gs.out[1]);
    //log("babyjub.order - e ", order - e);



}
component main = verifyKey(100);
