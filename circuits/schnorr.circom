pragma circom 2.1.6;

include "./circomlib/circuits/bitify.circom";
include "./circomlib/circuits/babyjub.circom";
include "./circomlib/circuits/sha256/sha256.circom";


/*
1. GenerateSig:
inputs: message, private key, k (nonce value)
outputs: R - [k]G, S - [k - xe]G

2. VerifyMessage:
inputs: message, public key, R, S

*/
template verifyMessage( k ) {

    signal input LSign[256];
    signal input RSign[256];
    signal input msg[k];
    signal input pubkey[2][256];

    signal output result;

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    var ORD = 21888242871839275222246405745257275088614511777268538073601725287587578984328;

    component shaHash = sha256(k);
}
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

component main = test();


