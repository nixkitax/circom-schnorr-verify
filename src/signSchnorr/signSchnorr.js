import { buildBabyjub } from 'circomlibjs';
import crypto from 'crypto';
import { buildPedersenHash } from 'circomlibjs';
import { Scalar } from 'ffjavascript';

import {
  arrayBytesToHex,
  hasEvenY,
  bigIntFromHex,
  byteArrayToInt,
  hexFromBigInt,
  hexToArrayBytes,
  hexToBigInt,
  intToByteArray,
  x,
  y,
  updateJson,
  returnPrivateKey,
} from '../utils/utils.js';

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

const babyJub = await buildBabyjub();
const pedersen = await buildPedersenHash();

export const signSchnorr = (msg, privateKey, type) => {
  const d0 = hexToBigInt(privateKey);

  if (d0 > babyJub.order - 1n)
    throw new Error('prvKey has to be less than order-1 ');

  let P = babyJub.mulPointEscalar(babyJub.Base8, d0);
  let d; //private key
  if (hasEvenY(P)) d = d0;
  else d = babyJub.order - d0;

  const nonceValue = crypto.randomBytes(32);

  const pPubKey = babyJub.packPoint(P);

  // STILL PUT STANDARD NONCE
  const hashMsg = crypto
    .createHash('sha256')
    .update('HOPE2SEEUAGA')
    .digest('hex');
  const combinedHash = crypto
    .createHash('sha256')
    .update(hashMsg + nonceValue + hashMsg)
    .digest('hex');

  const k0 = hexToBigInt(combinedHash) % babyJub.order;

  // r = G^k

  const r = babyJub.mulPointEscalar(babyJub.Base8, k0);

  const composeBuff2 = new Uint8Array(32 + msg.length);

  composeBuff2.set(intToByteArray(x(r)), 0);
  composeBuff2.set(msg, 32);

  const hmBuff = pedersen.hash(composeBuff2);

  const e = byteArrayToInt(hmBuff) % babyJub.order;

  const prova = Scalar.sub(k0, Scalar.mul(d, e));
  console.log(prova);
  console.log((k0 + d * e) % babyJub.order);

  const LSign = hexFromBigInt(x(r));
  const RSign = hexFromBigInt((k0 + d * e) % babyJub.order);
  const signature = LSign.concat(RSign);

  switch (type) {
    case 'verKey':
      return verifySignature(pPubKey, msg, signature, 'verKey');
    case 'sign':
      console.log('');
      console.log('> \x1b[32m[signSchnorr] \x1b[0md:            ', d);
      console.log('> \x1b[32m[signSchnorr] \x1b[0mk             ', k0);
      console.log('> \x1b[32m[signSchnorr] \x1b[0me:            ', e);
      console.log('> \x1b[32m[signSchnorr] \x1b[0mx(r):         ', x(r));
      console.log(
        '> \x1b[32m[signSchnorr] \x1b[0mn:            ',
        babyJub.order
      );
      console.log('');
      console.log(
        '> \x1b[32m[signSchnorr] \x1b[0m[LSign][RSign] (bigInt): ',
        '\n\n\t   [',
        bigIntFromHex(LSign),
        ']\n\t   [',
        bigIntFromHex(RSign),
        ']\n'
      );
      console.log(
        '> \x1b[32m[signSchnorr] \x1b[0m([LSign][RSign]) (HEX): ',
        '\n\n\t   [',
        LSign + RSign,
        ']\n'
      );
      console.log('> \x1b[32m[signSchnorr] \x1b[0mmessage:      ', msg);
      console.log(
        '> \x1b[32m[signSchnorr]\x1b[0m publicKey:    ',
        arrayBytesToHex(pPubKey)
      );
      console.log('> \x1b[32m[signSchnorr]\x1b[0m privateKey:   ', privateKey);

      var isOK = verifySignature(pPubKey, msg, signature, 'verKey');
      if (isOK) {
        console.log(
          '> \x1b[32m[signSchnorr]\x1b[0m Sign status:   \x1b[32mokay\x1b[0m '
        );
      } else
        console.log(
          '> \x1b[32m[signSchnorr]\x1b[0m Sign status:   \x1b[31mnot okay\x1b[0m'
        );
      //console.log( hexToArrayBytes(arrayBytesToHex(pPubKey)))
      //return verifySignature(pPubKey, msg, signature, "verify");
      break;
    case 'signC':
      console.log('');
      console.log('> \x1b[32m[signSchnorr] \x1b[0md:            ', d);
      console.log('> \x1b[32m[signSchnorr] \x1b[0mk             ', k0);
      console.log('> \x1b[32m[signSchnorr] \x1b[0me:            ', e);
      console.log('> \x1b[32m[signSchnorr] \x1b[0mx(r):         ', x(r));
      console.log(
        '> \x1b[32m[signSchnorr] \x1b[0mn:            ',
        babyJub.order
      );
      console.log('');
      console.log(
        '> \x1b[32m[signSchnorr] \x1b[0m[LSign][RSign] (bigInt): ',
        '\n\n\t   [',
        bigIntFromHex(LSign),
        ']\n\t   [',
        bigIntFromHex(RSign),
        ']\n'
      );
      console.log(
        '> \x1b[32m[signSchnorr] \x1b[0m([LSign][RSign]) (HEX): ',
        '\n\n\t   [',
        LSign + RSign,
        ']\n'
      );
      console.log('> \x1b[32m[signSchnorr] \x1b[0mmessage:      ', msg);
      console.log(
        '> \x1b[32m[signSchnorr]\x1b[0m publicKey:    ',
        arrayBytesToHex(pPubKey)
      );
      console.log('> \x1b[32m[signSchnorr]\x1b[0m privateKey:   ', privateKey);

      var isOK = verifySignature(pPubKey, msg, signature, 'verKey');
      if (isOK) {
        console.log(
          '> \x1b[32m[signSchnorr]\x1b[0m Sign status:   \x1b[32mokay\x1b[0m '
        );
        /*
        console.log(
          '> RSign => ',
          bigIntFromHex(RSign),
          '\n> RSign binary => ',
          SJson,
          '\n> RSign array binary => ',
          SJson.split('').map(Number)
        );
        
*/
        //console.log(pPubBits);
        //console.log(buffer2bits(Buffer.from(bigIntFromHex(LSign), 'hex')));
        const jsonObject = {
          LSign: bigIntFromHex(LSign).toString(),
          RSign: bigIntFromHex(RSign).toString(),
          msg: msg,
          pPub: byteArrayToInt(pPubKey).toString(),
        };
        updateJson(jsonObject, '../json/input.json');
        console.log(
          '\n> \x1b[32m[signSchnorr]\x1b[0m Created\x1b[34m input.json \x1b[0mfor circom!'
        );
      } else
        console.log(
          '> \x1b[32m[signSchnorr]\x1b[0m Sign status:   \x1b[31mnot okay\x1b[0m'
        );
      //console.log( hexToArrayBytes(arrayBytesToHex(pPubKey)))
      //return verifySignature(pPubKey, msg, signature, "verify");
      break;
    case 'default':
      console.error('There is unknown paramaters for schnorr_sign');
  }
};

/**
 * Verify a Schnorr signature.
 *
 * @param {string} pPubKey - The public key as a hexadecimal string.
 * @param {string} msg - The message as a hexadecimal string.
 * @param {string} signature - The signature as a hexadecimal string.
 * @param {string} type - The type of operation ("verKey", "verify").
 * @returns {boolean|void} - Returns `true` if verification succeeds (for "verKey" type), otherwise `void`.
 */
const verifySignature = (pPubKey, msg, signature, type) => {
  if (type == 'verify') pPubKey = hexToArrayBytes(pPubKey);

  let isOK;
  let P = babyJub.unpackPoint(pPubKey);
  const LSign = signature.slice(0, 64);
  const RSign = signature.slice(64);
  const R = bigIntFromHex(LSign);
  const s = bigIntFromHex(RSign);

  //console.log(x(P).toString(2).length);

  //console.log(hexToArrayBytes(LSign));
  const composeBuff2 = new Uint8Array(32 + msg.length);
  composeBuff2.set(hexToArrayBytes(LSign), 0);
  composeBuff2.set(msg, 32);
  //console.log('verify: ', hexToArrayBytes(msg));
  //console.log(composeBuff2);
  const hashBuff = pedersen.hash(composeBuff2);
  //console.log(byteArrayToInt(hmBuff) % babyJub.order);
  const e = byteArrayToInt(hashBuff) % babyJub.order;
  const gs = babyJub.mulPointEscalar(babyJub.Base8, s);
  const Pe = babyJub.mulPointEscalar(P, babyJub.order - e);
  const newR = babyJub.addPoint(gs, Pe);
  if (R == x(newR)) isOK = true;

  switch (type) {
    case 'verKey':
      if (isOK) return true;
      else break;
    case 'verify':
      console.log('> [verifySignature] e                   ', e);
      console.log('> [verifySignature] R:                  ', R);
      console.log('> [verifySignature] xnewPoint:          ', x(newR));
      if (isOK) console.log('\n\t\t\t\t\t  Verification is OK :)');
      break;
    default:
      console.error('There is an unknown parameter for verifySignature');
  }
};
