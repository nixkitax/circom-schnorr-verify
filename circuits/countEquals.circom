pragma circom  2.1.6;

include "./circomlib/circuits/comparators.circom";

template isTheSame() {
    signal input in[2];
    signal output out;

    component isz = IsZero();

    in[1] - in[0] ==> isz.in;

    isz.out ==> out;
}

template countEquals(N){

    signal input x[N];
    signal input y[N];
    signal output out;
    var sum;

    component ise[N];
    sum = 0;
    var i = 0;

    for(i = 0; i < N; i++){
        ise[i] = isTheSame();
    }

    for(i = 0; i < N; i++){
        ise[i].in[0] <== x[i];
        ise[i].in[1] <== y[i];
        sum = sum + ise[i].out; 
    }

    out <== sum;
    log("The expected result is ", N," and the value of same items is",out);

}