pragma circom 2.1.6;

include "./circomlib/circuits/comparators.circom";
include "./circomlib/circuits/compconstant.circom";
include "./circomlib/circuits/poseidon.circom";
include "./circomlib/circuits/bitify.circom";
include "./circomlib/circuits/escalarmulany.circom";
include "./circomlib/circuits/escalarmulfix.circom";

template isTheSame() {
    signal input in[2];
    signal output out;

    component isz = IsZero();

    in[1] - in[0] ==> isz.in;

    isz.out ==> out;
}

template Schnorr(gx, gy){
    signal input enabled;
    signal input message;

    signal input pubX;
    signal input pubY;

    signal input S;
    signal input e;

    signal output out;

    // Trasforming S to bits
    component snum2bits = Num2Bits(253);
    snum2bits.in <== S;

    // Trasforming e to bits
     component enum2bits = Num2Bits(254);
    enum2bits.in <== e;

    // 1) Calculate g^s
    component mulAny = EscalarMulAny(253);

    for(var i = 0; i<253; i++){
        mulAny.e[i] <== snum2bits.out[i];
    }
    mulAny.p[0] <== gx;
    mulAny.p[1] <== gy;

    // 2) Calculate y^e
    component mulAny1 = EscalarMulAny(254);
    for(var i = 0; i<254; i++){
        mulAny1.e[i] <== enum2bits.out[i];
    }
    mulAny1.p[0] <== pubX;
    mulAny1.p[1] <== pubY;

     //rv = g^sy^e (which is just adding g^s and y^e)
    component add1 = BabyAdd();
    add1.x1 <== mulAny.out[0];
    add1.y1 <== mulAny.out[1];
    add1.x2 <== mulAny1.out[0];
    add1.y2 <== mulAny1.out[1];


    // 3) Hash H(rv || M)
    component ev = Poseidon(3);
    ev.inputs[0] <== add1.xout;
    ev.inputs[1] <== add1.yout;
    ev.inputs[2] <== message;

     // 4) Check if e == ev
    component eqCheck = isTheSame();
    eqCheck.in[0] <== e;
    eqCheck.in[1] <== ev.out;

    out <== eqCheck.out

}

component main {public[enabled, message, pubX, pubY, S, e]} = Schnorr(
    5299619240641551281634865583518297030282874472190772894086521144482721001553,16950150798460657717958625567821834550301663161624707787222815936182638968203);
