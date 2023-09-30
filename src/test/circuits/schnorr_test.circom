pragma circom 2.1.6;

include "../../../circuits/countEquals.circom";

component main {public [x, y]} = countEquals(10);