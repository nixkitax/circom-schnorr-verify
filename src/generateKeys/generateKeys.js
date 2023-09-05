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
} from '../utils/utils.js';

import { signSchnorr } from '../signSchnorr/signSchnorr.js';

const babyJub = await buildBabyjub();

/**
 * Generates cryptographic key pairs and adds details to a JSON file.
 *
 * @param {number} numKeys - The number of key pairs to generate.
 * @returns {void}
 */
export const generateKeys = numKeys => {
  console.log(
    '> \x1b[32m[Key Generation] \x1b[0mGenerating',
    '[',
    numKeys,
    '] keys in "../../json/users.json"'
  );
  let count = 0;
  let object = {
    $schema: './users_schema.json',
    users: [],
  };

  while (count < numKeys) {
    /**
     * Generate a random private key as a byte array.
     *
     * @type {Buffer}
     */
    const InitPrvKeyBytes = crypto.randomBytes(32);

    /**
     * Convert the byte array to an integer.
     *
     * @type {bigint}
     */
    const InitPrvKeyInt = byteArrayToInt(InitPrvKeyBytes) % babyJub.order;

    /**
     * Multiply the base public key by the private key.
     *
     * @param {object} point - Point on the elliptic curve.
     * @param {number} privateKey - The private key.
     * @returns {object} - The resulting public key point.
     */
    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, InitPrvKeyInt);

    /**
     * Determine the private key based on Y evenness.
     *
     * @type {bigint}
     */
    let prvKey;
    if (hasEvenY(pubKey)) prvKey = InitPrvKeyInt;
    else prvKey = babyJub.order - InitPrvKeyInt;

    /**
     * Convert the public key to a byte array and then to a hexadecimal string.
     *
     * @type {string}
     */
    const pPubKey = babyJub.packPoint(pubKey);
    const pubKeyHex = arrayBytesToHex(pPubKey);

    /**
     * Convert the private key to a hexadecimal string.
     *
     * @type {string}
     */
    const prvKeyHex = hexFromBigInt(prvKey);

    /**
     * Generate a random message as a hexadecimal string.
     *
     * @type {string}
     */
    const msg = arrayBytesToHex(crypto.randomBytes(32));

    /**
     * Verify the key pair using the message and the private key.
     *
     * @type {boolean}
     */
    const isKeyGood = verifyKeyPair(msg, prvKeyHex, 'verKey');
    if (isKeyGood) {
      object.users.push({ publicKey: pubKeyHex, privateKey: prvKeyHex });
      count++;
    }
  }

  console.log(
    '> \x1b[32m[Key Generation] \x1b[0mGenerated [',
    numKeys,
    '] keys in "../json/users.json"'
  );

  /**
   * Update the JSON file with the generated key pairs.
   *
   * @type {void}
   */
  updateJson(object, '../json/users.json');
};

/**
 * Verify a key pair using Schnorr signature.
 *
 * @param {string} msg - The message to sign as a hexadecimal string.
 * @param {string} prvKeyHex - The private key as a hexadecimal string.
 * @returns {boolean} - `true` if verification succeeds, otherwise `false`.
 */
const verifyKeyPair = (msg, prvKeyHex) => {
  return signSchnorr(msg, prvKeyHex, 'verKey');
};
