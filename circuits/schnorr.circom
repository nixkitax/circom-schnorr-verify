pragma circom 2.1.6;

include "./circomlib/circuits/bitify.circom";
include "./circomlib/circuits/babyjub.circom";
include "./circomlib/circuits/pedersen.circom";
include "./circomlib/circuits/sha256/sha256.circom";
include "./circomlib/circuits/pointbits.circom";


template verifyKey(){
  

  signal input A[256];
  component pointbits = Bits2Point_Strict();


}
/*
   

        var k;

        component shaHash = Sha256(nBits + 512);

        for(k=0; k<256; k++){
          shaHash.in[k] <== R[k];
          shaHash.in[k + 256] <== pubKey[k];
        }
        
        for(k=0; k<nBits; k++){
          shaHash.in[ k + 512] <== msg[k]
        }

        component bits2pointpubkey = Bits2Point_Strict();

    for (i=0; i<256; i++) {
        bits2pointpubkey.in[i] <== pPub[i];
    }
    xPubKey <== bits2pointpubkey.out[0];
    yPubKey <== bits2pointpubkey.out[1];

    //hash per il messaggio
    component shaMSG = Sha256(k);

    for(var i = 0; i < k; i ++ ){
      shaMSG.in[i] <== msg[i];
    }

    //hash per -> e
    component sha256 = Sha256(512 + k);

    for (var i = 0; i < 256; i++) {
      sha256.in[i] <== lSign[i];
    }

    for(var i = 0; i < 256; i++){
      sha256.in[i + 256] <== pPub[i];

    }

    for (var i = 0; i < k; i++){
      sha256.in[i + 512] <== shaMSG.out[i];
    }

    for(var i = 0; i < 256; i++){
      hash[i] = sha256.out[i]; // Use = for variable assignments
    }

    log(135);

/*
    component mulFix = EscalarMulFix(256, BASE8);

    for (i=0; i<256; i++) {
        mulFix.e[i] <== rSign[i];
    }


*/
     // hash ( lsign + xPubKey + msg )

    /*
      const gs = babyJub.mulPointEscalar(babyJub.Base8, s);
      const Pe = babyJub.mulPointEscalar(P, babyJub.order - e);
      const newR = babyJub.addPoint(gs, Pe);
      if (R == x(newR)) isOK = true;
    */

/*
const verifySignature = (pPubKey, msg, signature, type) => {
  if (type == 'verify') pPubKey = hexToArrayBytes(pPubKey);

  let isOK;
  let P = babyJub.unpackPoint(pPubKey);
  const LSign = signature.slice(0, 64);
  const RSign = signature.slice(64);
  const R = bigIntFromHex(LSign);
  const s = bigIntFromHex(RSign);
  const concatHash = LSign + hexFromBigInt(x(P)) + msg;
  const e =
    hexToBigInt(crypto.createHash('sha256').update(concatHash).digest('hex')) %
    babyJub.order;
  const gs = babyJub.mulPointEscalar(babyJub.Base8, s);
  const Pe = babyJub.mulPointEscalar(P, babyJub.order - e);
  const newR = babyJub.addPoint(gs, Pe);
  if (R == x(newR)) isOK = true;

*/

component main {  } = verifyKey();
