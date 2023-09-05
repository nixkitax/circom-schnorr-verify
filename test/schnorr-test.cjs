import { assert } from 'chai';
import path, { dirname } from 'path'; // Importa "path" e "dirname" da "path"
import { wasm } from 'circom_tester';
import { buildBabyjub } from 'circomlibjs';
import { Scalar } from 'ffjavascript';

import { signSchnorr } from '../src/signSchnorr/signSchnorr.js';

function print(circuit, w, s) {
  console.log(s + ': ' + w[cilrcuit.getSignalIdx(s)]);
}

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

describe('Schnorr test', function () {
  let circuit;
  let babyJub;
  let F;
  const __dirname = path.dirname(require.main.filename);
  this.timeout(100000);

  before(async () => {
    babyJub = await buildBabyjub();
    F = babyJub.F;
    circuit = await wasm(path.join(__dirname, 'circuits', 'schnorr.circom'));
  });

  it('Sign a single 10 bytes from 0 to 9', async () => {
    const msg = Buffer.from(
      'ed3f690c1008aa985b973488be4e54b8ac510bcaf7d5ae0ff8cf8e7469daab63',
      'hex'
    );

    //        const prvKey = crypto.randomBytes(32);

    const prvKey = Buffer.from(
      '24d47a780f8ef2a7f18fb48fcb2170972b22bfaee46a529c044dadfe57449fb0',
      'hex'
    );

    const pPubKey =
      'bad339b31ffa45a95f724d15dc9506e6c55f86d04cbd7e4d8d7fb2e14ab35224';

    console.log(signSchnorr(msg, prvKey, 'sign'));

    /*
    const msgBits = buffer2bits(msg);
    const r8Bits = buffer2bits(pSignature.slice(0, 32));
    const sBits = buffer2bits(pSignature.slice(32, 64));
    const aBits = buffer2bits(pPubKey);

    const w = await circuit.calculateWitness(
      { A: aBits, R8: r8Bits, S: sBits, msg: msgBits },
      true
    );

    await circuit.checkConstraints(w);
    */
  });
});
