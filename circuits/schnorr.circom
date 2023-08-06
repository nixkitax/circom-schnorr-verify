pragma circom 2.1.6;

include "./circomlib/circuits/poseidon.circom";
include "./circomlib/circuits/bitify.circom";


    
template verifySchnorrSignature() {
    /*
        Definition:
            - message: original signed messsage;
            - r: value of the signature;
            - P: value of public key;
            - e: value of the challenge by the verifier.
        The circuit produces an ouput called isValid, which indicates whether 
        the Schnorr signature is valid or not with respect to the publick key P.
    */
    signal input pubKeys[10]; //set delle chiavi pubbliche conosciute
    signal input signatureSchnorr; //firma di schnorr
    signal input message;  
    signal input r;
    signal input P;
    signal input e;
    signal isValid;


    signal hashedMessage;
    hashedMessage <== hash.hash(message);

    signal R;
    R <== r * G;

    signal eP;
    eP <== e * P;

    signal R_plus_eP;
    R_plus_eP <== R + eP;

    signal hashed_R_plus_eP;
    hashed_R_plus_eP <== hash.hash(R_plus_eP);

    isValid <== hashed_R_plus_eP === hashedMessage;

    output isValid;
    */
    signal input a;
    signal output b;

    b <== a;
    log("just to try");
}

component main = VerifySchnorrSignature();

