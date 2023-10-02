import path from 'path';
import circom_tester from 'circom_tester';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { Scalar } from 'ffjavascript';
import { buildSchnorr } from './schnorrhelper.js';

const wasm_tester = circom_tester.wasm;
let schnorr, babyJub, F;
var num_constraints;

function generateRandomBigInt(maxBits) {
  const words = Math.ceil(maxBits / 32);
  const arr = new Uint32Array(words);
  crypto.getRandomValues(arr);
  // clear any excess bits in the last word
  const excessBits = words * 32 - maxBits;
  if (excessBits > 0) {
    const mask = (1 << (32 - excessBits)) - 1;
    arr[words - 1] &= mask;
  }
  return BigInt(arr.join(''));
}

(async () => {
  schnorr = await buildSchnorr();
  babyJub = await buildBabyjub();
  F = babyJub.F;
  let circuit = await wasm_tester(
    path.join(process.cwd(), 'circuits', 'schnorr_test.circom')
  );
  await circuit.loadConstraints();
  num_constraints = circuit.constraints.length;
  console.log('Schnorr #Constraints:', num_constraints);

  let msg = F.e(1234);
  msg = F.toObject(msg);
  console.log(msg);
  const prvKey = generateRandomBigInt(253);

  //random integer selected by the verifier
  const k = generateRandomBigInt(253);

  //obtain private key from public key
  const pubKey = schnorr.prv2pub(prvKey);

  //obtain the signature
  const signature = schnorr.signPoseidon(prvKey, msg, k);
  //verify that everything is correct

  if (schnorr.verifyPoseidon(signature, pubKey, msg)) {
    let input = {
      enabled: '1',
      message: msg.toString(),
      pubX: [F.toObject(pubKey[0]).toString()],
      pubY: [F.toObject(pubKey[1]).toString()],
      S: signature.s.toString(),
      e: signature.e.toString(),
    };
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);
    console.log(w);
  }
})();
