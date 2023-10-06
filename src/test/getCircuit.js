import path from 'path';
import circom_tester from 'circom_tester';
import { buildBabyjub } from 'circomlibjs';
import { buildSchnorr } from '../utils/schnorrhelper.js';
import {
  updateJson,
  stringToBigInt,
  generateRandomBigInt,
  getR1CSInfo,
} from '../utils/utils.js';

const wasm_tester = circom_tester.wasm;
const circuitName = 'schnorr_test.circom';
let schnorr, babyJub, F;

export const generateWitness = (message, number, index) => {
  (async () => {
    schnorr = await buildSchnorr();
    babyJub = await buildBabyjub();
    F = babyJub.F;
    let circuit = await wasm_tester(
      path.join(process.cwd(), '/test/circuits', circuitName)
    );
    await circuit.loadConstraints();

    let msg = F.e(stringToBigInt(message));
    msg = F.toObject(msg);

    getR1CSInfo(circuitName);

    let privateKeys = [];
    let publicKeysX = [];
    let publicKeysY = [];

    for (let i = 0; i < number; i++) {
      const prvKey = generateRandomBigInt(253);
      const pubKey = schnorr.prv2pub(prvKey);
      privateKeys.push(prvKey);
      publicKeysX.push(F.toObject(pubKey[0]).toString());
      publicKeysY.push(F.toObject(pubKey[1]).toString());
    }

    const k = generateRandomBigInt(253);
    const prvKey = privateKeys[index];
    const pubKey = schnorr.prv2pub(prvKey);
    const signature = schnorr.signPoseidon(prvKey, msg, k);

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
