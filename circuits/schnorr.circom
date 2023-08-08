pragma circom 2.1.6;
    
template verifySchnorrSignature() {
    signal input mmessage;
    signal input signature;
    signal input num_keys;
    signal input public_keys[500];
}

component main = verifySchnorrSignature();

