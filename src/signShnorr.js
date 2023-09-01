import { buildBabyjub } from 'circomlibjs';
import crypto from 'crypto';

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
} from './utils.js';

const babyJub = await buildBabyjub();

export const signSchnorr = (msg, privateKey, type) => {
  const d0 = hexToBigInt(privateKey);
  if (d0 > babyJub.order - 1n)
    throw new Error('prvKey has to be minor than order-1 ');
  let P = babyJub.mulPointEscalar(babyJub.Base8, d0);
  let d; //private key
  if (hasEvenY(P)) d = d0;
  else d = babyJub.order - d0;
  const nonceValue = crypto.randomBytes(32);
  const hashMsg = crypto
    .createHash('sha256')
    .update('HOPE2SEEUAGA')
    .digest('hex');
  const combinedHash = crypto
    .createHash('sha256')
    .update(hashMsg + nonceValue + msg)
    .digest('hex');
  const k0 = hexToBigInt(combinedHash) % babyJub.order;
  const r = babyJub.mulPointEscalar(babyJub.Base8, k0);
  const concatHash = hexFromBigInt(x(r)) + hexFromBigInt(x(P)) + msg;
  const e =
    hexToBigInt(crypto.createHash('sha256').update(concatHash).digest('hex')) %
    babyJub.order;
  const LSign = hexFromBigInt(x(r));
  const RSign = hexFromBigInt((k0 + d * e) % babyJub.order);
  const pPubKey = babyJub.packPoint(P);
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
      console.log('');
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
        const jsonObject = {
          LSign: signature.slice(0, 64),
          RSign: signature.slice(64),
          msg: msg,
          pPub: arrayBytesToHex(pPubKey),
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

  switch (type) {
    case 'verKey':
      if (isOK) return true;
      else break;
    case 'verify':
      console.log('> [verifySignature] R:                  ', R);
      console.log('> [verifySignature] xnewPoint:          ', x(newR));
      if (isOK) console.log('\n\t\t\t\t\t  Verification is OK :)');
      break;
    case 'default':
      console.error('There is unknown paramaters for verifySignature');
  }
};
