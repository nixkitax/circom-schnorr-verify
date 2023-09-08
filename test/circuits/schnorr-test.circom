pragma circom 2.1.6;

include "../../circuits/schnorr.circom";

component main {public [r, s, msg, pubkey]} = verifyKey(64, 4);