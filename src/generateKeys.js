import crypto from 'crypto';
import { buildBabyjub } from 'circomlibjs';

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

import { signSchnorr } from './signShnorr.js';

const babyJub = await buildBabyjub();

export const generateKeys = numKeys => {
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
