import path from 'path';
import circom_tester from 'circom_tester';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { Scalar } from 'ffjavascript';
import crypto from 'crypto';

import { buildSchnorr } from '../utils/schnorrhelper.js';
import fs from 'fs';
import { updateJson } from '../utils/utils.js';

const wasm_tester = circom_tester.wasm;
let schnorr, babyJub, F;
var num_constraints;

const stringToBigInt = input => {
  const hash = crypto.createHash('sha256').update(input).digest('hex');
  return BigInt(`0x${hash}`);
};

const generateRandomBigInt = maxBits => {
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
};

export const generateWitness = (message, number, index) => {
  (async () => {
    schnorr = await buildSchnorr();
    babyJub = await buildBabyjub();
    F = babyJub.F;
    let circuit = await wasm_tester(
      path.join(process.cwd(), '/test/circuits', 'schnorr_test.circom')
    );
    await circuit.loadConstraints();
    num_constraints = circuit.constraints.length;
    console.log('Schnorr #Constraints:', num_constraints);

    let msg = F.e(stringToBigInt(message));
    msg = F.toObject(msg);

    let privateKeys = [];
    let publicKeysX = [];
    let publicKeysY = [];

    // Genera il numero specificato di coppie di chiavi private/pubbliche
    for (let i = 0; i < number; i++) {
      const prvKey = generateRandomBigInt(253);
      const pubKey = schnorr.prv2pub(prvKey);

      privateKeys.push(prvKey);
      publicKeysX.push(F.toObject(pubKey[0]).toString());
      publicKeysY.push(F.toObject(pubKey[1]).toString());
    }

    //random integer selected by the verifier
    const k = generateRandomBigInt(253);

    // Choose the private key to use based on the specified index
    const prvKey = privateKeys[index];
    const pubKey = schnorr.prv2pub(prvKey);

    //obtain the signature
    const signature = schnorr.signPoseidon(prvKey, msg, k);
    //verify that everything is correct

    if (schnorr.verifyPoseidon(signature, pubKey, msg)) {
      let input = {
        enabled: '1',
        message: msg.toString(),
        pubX: publicKeysX,
        pubY: publicKeysY,
        S: signature.s.toString(),
        e: signature.e.toString(),
      };

      console.log(input);

      updateJson(input, '../json/inputCircuit.json');

      const w = await circuit.calculateWitness(input, true);
      await circuit.checkConstraints(w);
      console.log('Done, circuit verified :)');
      //console.log(w);
    }
  })();
};
