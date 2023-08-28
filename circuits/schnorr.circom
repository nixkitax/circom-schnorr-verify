pragma circom 2.1.6;

include "./circomlib/circuits/bitify.circom";
include "./circomlib/circuits/babyjub.circom";
include "./circomlib/circuits/sha256/sha256.circom";


/*
1. GenerateSig:
inputs: message, private key, k (nonce value)
outputs: R - [k]G, S - [k - xe]G

2. VerifyMessage:
inputs: message, public key, R, S
*/

template generateSig(message, privateKey, k) {
    
    signal input msg[nBitsMsg];
    
    signal input Lsign[256]; // R : L_Sign
    signal input Rsign[256]; // s : R_Sign
    signal input privateKey[256];    // pubKey

    signal xPubKey;
    signal yPubKey;

    component bits2pointPubKey = Bits2Point_Strict();

    component extractPublicKey = BabyPbk();

     for (i=0; i<254; i++) {
        extractPublicKey.in <== privateKey[i];
    }

    xPubKey <== extractPublicKey.Ax;
    yPubKey <== extractPublicKey.Ay;

    for (i=0; i<256; i++) {
        bits2pointA.in[i] <== A[i];
    }
    xPubKey <== bits2pointA.out[0];
    yPubKey <== bits2pointA.out[1];


    // Calculate H( R || pubKey || msg):
    // Signature 64 byte / 2  := Lsign, Rsign  


    // shaHash(R || P || msg) := out[256]


    //TODO: check g^s + P ^ (-e) == R ?? ==> 
    // G ^ R_Sign + pubKey ^ (-e ) == L_Sign ???

}

template verifyMessage( message, publicKey, R, S) {

    signal input message;
    signal input A;
    signal input R;
    signal input S;

    component bits2pointA = Bits2Point_Strict();

    for (i=0; i<256; i++) {
        bits2pointA.in[i] <== A[i];
    }
    Ax <== bits2pointA.out[0];
    Ay <== bits2pointA.out[1];

     component bits2pointA = Bits2Point_Strict();

    for (i=0; i<256; i++) {
        bits2pointA.in[i] <== A[i];
    }
    Ax <== bits2pointA.out[0];
    Ay <== bits2pointA.out[1];


}