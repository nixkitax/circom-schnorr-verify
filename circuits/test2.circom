pragma circom  2.1.6;

template ciauz(){
   signal input x;
   signal input y;

   signal output c;

   c <== x+y;

   log(c);
}