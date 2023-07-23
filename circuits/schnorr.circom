pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "bigint.circom";
include "secp256k1_func.circom";
include "secp256k1_utils.circom";

// Definizione dei segnali
signal input privateKey[256];
signal output publicKey[2][256]; // Pubblica chiave (x, y)

// Punto generatore della curva secp256k1
const Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
const Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424;

// Generazione chiave pubblica utilizzando la curva ellittica secp256k1
component secp256k1_scalar_mult = Secp256k1ScalarMult(256, 4);

for (var i = 0; i < 256; i++) {
    secp256k1_scalar_mult.scalar[i] <== privateKey[i];
}

// Output della chiave pubblica (P = G * privateKey)
for (var i = 0; i < 256; i++) {
    output[0][i] <== secp256k1_scalar_mult.out[0][i];
    output[1][i] <== secp256k1_scalar_mult.out[1][i];
}

