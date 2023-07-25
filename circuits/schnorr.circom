pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "secp256k1_func.circom";
include "secp256k1_utils.circom";
    
template VerifySchnorrSignature() {
    /*
        Definition:
            - message: original signed messsage;
            - r: value of the signature;
            - P: value of public key;
            - e: value of the challenge by the verifier.
        The circuit produces an ouput called isValid, which indicates whether 
        the Schnorr signature is valid or not with respect to the publick key P.
    
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

    /*
    signal message = 0x12345678; // Inserisci il messaggio firmato
    signal r = 0xdeadbeef; // Inserisci il valore della firma (r)
    signal P = 0xabcdef01; // Inserisci il valore della chiave pubblica (P)
    signal e = 0x98765432; // Inserisci il valore della sfida generata dal verificatore (e)

    signal isValid;

    VerifySchnorrSignature() verif {
        .message = message,
        .r = r,
        .P = P,
        .e = e,
        .isValid = isValid,
    }

    // Output del risultato della verifica
    output isValid;
    */
