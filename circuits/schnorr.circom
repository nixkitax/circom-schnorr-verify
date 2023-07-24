pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "bigint.circom";
include "secp256k1_func.circom";
include "secp256k1_utils.circom";

/*
#todo: 
input:
- Messaggio originale (testo o dati) che è stato firmato: denotato come message.
- Firma di Schnorr composta da due componenti:
    - Il valore della firma (r): denotato come r.
    - Il valore della chiave pubblica (P): denotato come P.
- La sfida generata dal verificatore (e): denotato come e. Nella firma di Schnorr, 
  questa sfida viene generata utilizzando la funzione hash crittografica (ad esempio SHA-256) del messaggio firmato.
"*/
    
template VerifySchnorrSignature() {
    signal message, r, P, e;
    signal isValid;

    // Calcola l'hash crittografico del messaggio firmato
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
}

component Main() {
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
}