pragma circom 2.1.6;

include "../../../circuits/verifyKeySchnorrGroup.circom";

component main {public[enabled, message, pubX, pubY, S, e]} = verifyKeySchnorrGroup(1);
