pragma circom 2.1.6;

include "./circomlib/circuits/compconstant.circom";
include "./circomlib/circuits/pointbits.circom";
include "./circomlib/circuits/sha256/sha256.circom";


template verifySchnorrSignature(nBitsMsg) {
    
    signal input msg[nBitsMsg];
    
    signal input Lsign[256]; // R : L_Sign
    signal input Rsign[256]; // S : R_Sign
    signal input pubKey[256];    // pubKey

    signal e[256];

    // Calculate H( R || pubKey || msg):
    // Signature 64 byte / 2  := Lsign, Rsign  



    component shaHash = Sha256(512 + nBitsMsg);

    for (var i=0; i<256; i++) {
        shaHash.in[i] <== Lsign[i];
        shaHash.in[256+i] <== pubKey[i];
    }

    for (var i=0; i<nBitsMsg; i++) {
        shaHash.in[512+i] <== msg[i];
    }
  

    // shaHash(R || P || msg) := out[256]


    for (var i=0; i<256; i++) {
        e[i] <== shaHash.out[i];

    }

    //TODO: check g^s + P ^ (-e) == R ?? ==> 
    // G ^ R_Sign + pubKey ^ (-e ) == L_Sign ???

}
