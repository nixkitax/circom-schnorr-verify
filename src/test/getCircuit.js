import path from 'path';
import circom_tester from 'circom_tester';
import fs from 'fs';

const wasm_tester = circom_tester.wasm;

function buffer2bits(buff) {
  const res = [];
  for (let i = 0; i < buff.length; i++) {
    for (let j = 0; j < 8; j++) {
      if ((buff[i] >> j) & 1) {
        res.push(1n);
      } else {
        res.push(0n);
      }
    }
  }
  return res;
}
/*
const produceInputCircuit = () => {
  try {
    const file = fs.readFileSync('../../json/input.json', 'utf8');
    const dati = JSON.parse(file);
    const LSign = dati.LSign;
    const RSign = dati.RSign;
    const msg = dati.msg;
    const pPub = dati.pPub;
    return { LSign, RSign, msg, pPub };
  } catch (errore) {
    console.error(
      'Si è verificato un errore nella lettura del file JSON:',
      errore
    );
    return null;
  }
};
*/
let circuit = await wasm_tester(
  path.join(process.cwd(), 'circuits', 'schnorr_test.circom')
);

/*
const { LSign, RSign, msg, pPub } = produceInputCircuit();

const buffMsg = Buffer.from(msg, 'hex');
const bitsMsg = buffer2bits(buffMsg);
*/
let witness = await circuit.calculateWitness({ enabled: 1, x: 4, y: 4 });

console.log(witness);
