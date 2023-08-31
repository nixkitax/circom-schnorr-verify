import crypto from 'crypto';
import { buildBabyjub } from 'circomlibjs';
import { ArgumentParser } from 'argparse';
import fs from 'fs';

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

const generateKeys = numKeys => {
  console.log(
    '> \x1b[32m[Generation Key] \x1b[0mGenerating',
    '[',
    numKeys,
    '] keys in "../json/users.json'
  );
  let count = 0;
  let object = {
    $schema: './users_schema.json',
    users: [],
  };

  while (count < numKeys) {
    const InitPrvKeyBytes = crypto.randomBytes(32);
    const InitPrvKeyInt = byteArrayToInt(InitPrvKeyBytes) % babyJub.order;
    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, InitPrvKeyInt);
    let prvKey;
    if (hasEvenY(pubKey)) prvKey = InitPrvKeyInt;
    else prvKey = babyJub.order - InitPrvKeyInt;
    const pPubKey = babyJub.packPoint(pubKey);
    const pubKeyHex = arrayBytesToHex(pPubKey);
    const prvKeyHex = hexFromBigInt(prvKey);
    const msg = arrayBytesToHex(crypto.randomBytes(32));

    const isKeyGood = verifyKeyPair(msg, prvKeyHex, 'verKey');
    if (isKeyGood) {
      object.users.push({ publicKey: pubKeyHex, privateKey: prvKeyHex });
      count++;
    }
  }

  console.log(
    '> \x1b[32m[Generation Key] \x1b[0mGenerating [',
    numKeys,
    '] keys in "../json/users.json'
  );
  updateJson(object, '../json/users.json');
};

const verifyKeyPair = (msg, prvKeyHex) => {
  return signSchnorr(msg, prvKeyHex, 'verKey');
};

const returnPublicKey = async index => {
  try {
    const data = await fsp.readFile('../json/users.json', 'utf8');
    const jsonData = JSON.parse(data);
    const publicKey = jsonData.users[0].publicKey;

    return publicKey;
  } catch (err) {
    console.error('Errore:', err);
    throw err;
  }
};

const signSchnorr = (msg, privateKey, type) => {
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

(async () => {
  try {
    const parser = new ArgumentParser({
      description:
        'Command-line tool for generating and verifying Schnorr cryptographic keys and signatures.',
    });

    parser.add_argument('-g', '--generateKeys', {
      action: 'store_true',
      help: 'Generate keys',
    });
    parser.add_argument('-n', '--number', {
      type: Number,
      help: 'Number of keys to generate',
      required: false,
      default: 1,
    });
    parser.add_argument('-c', '--createSignature', {
      action: 'store_true',
      help: 'creation of a signature',
      required: false,
    });
    parser.add_argument('-i', '--index', {
      type: Number,
      help: 'index of a privateKey',
      required: false,
      default: 0,
    });
    parser.add_argument('-m', '--message', {
      type: String,
      help: 'Message to sign',
      required: false,
      default: arrayBytesToHex(crypto.randomBytes(32)),
    });
    parser.add_argument('-v', '--verifySign', {
      action: 'store_true',
      help: 'verify s signature',
      required: false,
    });
    parser.add_argument('-p', '--pPubKey', {
      type: String,
      help: 'publicKey to verify a signature',
      required: false,
      default: ' ',
    });
    parser.add_argument('-s', '--signature', {
      type: String,
      help: 'signature to verify',
      required: false,
      default: ' ',
    });
    parser.add_argument('-orm', '--originalMsg', {
      type: String,
      help: 'original message to verify',
      required: false,
      default: ' ',
    });
    parser.add_argument('-circom', '--circomJSON', {
      action: 'store_true',
      help: 'pin if you want json for circom',
      required: false,
    });

    const args = parser.parse_args();
    if (args.generateKeys) generateKeys(args.number);
    if (args.createSignature) {
      if (fs.existsSync('../json/users.json')) {
        fs.readFile('../json/users.json', 'utf8', async (err, data) => {
          if (err) {
            console.error('Errore nella lettura del file:', err);
            return;
          }
          try {
            const jsonData = JSON.parse(data);
            const numberOfPublicKeys = jsonData.users.length;
            if (args.index > numberOfPublicKeys) {
              console.error(
                '> Error in execution: Index (-i) is out of bounds, there are ',
                numberOfPublicKeys,
                ' keys in users.json (first one -> 0)'
              );
              process.exit(1);
            }
            const privateKey = await returnPrivateKey(args.index);
            if (args.circomJSON) signSchnorr(args.message, privateKey, 'signC');
            else signSchnorr(args.message, privateKey, 'sign');
          } catch (parseError) {
            console.error('Errore nel parsing del JSON:', parseError);
          }
        });
      } else {
        console.error(
          `> Error in execution: You have to generate your keys with: node schnorr_lib.js -g -n numKeys, look at https://github.com/lyylaaa/circom-schnorr-verify`
        );
        process.exit(1);
      }
    }
    if (args.verifySign) {
      if (args.pPubKey == ' ')
        console.error(
          'You have to insert a compressed public key [HEX] to verify a signature, node schnorr.js -h'
        );
      if (args.signature == ' ')
        console.error(
          'You have to insert a signature [HEX] to verify a signature, node schnorr.js -h'
        );
      if (args.originalMsg == ' ')
        console.error(
          'You have to insert the original message to verify a signature, node schnorr.js -h'
        );
      //console.log(args.originalMsg);
      verifySignature(args.pPubKey, args.originalMsg, args.signature, 'verify');
    }
  } catch (error) {
    console.error('Si è verificato un errore:', error);
  }
})();
