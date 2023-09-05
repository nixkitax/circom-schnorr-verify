import fs from 'fs';
import fsp from 'fs/promises';

/**
 * Check if the Y-coordinate of a point on the elliptic curve is even.
 *
 * @param {object} P - Point on the elliptic curve.
 * @returns {boolean} - `true` if Y-coordinate is even, `false` otherwise.
 */
export const hasEvenY = P => y(P) % 2n == 0n;

/**
 * Convert an array of bytes to a hexadecimal string.
 *
 * @param {Array<number>} bytes - Array of bytes.
 * @returns {string} - Hexadecimal string representation.
 */
export const arrayBytesToHex = bytes => {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * Convert a hexadecimal string to an array of bytes.
 *
 * @param {string} hexString - Hexadecimal string.
 * @returns {Array<number>} - Array of bytes.
 */
export const hexToArrayBytes = hexString => {
  const bytes = [];
  for (let i = 0; i < hexString.length; i += 2) {
    bytes.push(parseInt(hexString.substr(i, 2), 16));
  }
  return bytes;
};

/**
 * Convert an array of bytes to a BigInt.
 *
 * @param {Array<number>} byteArray - Array of bytes.
 * @returns {bigint} - BigInt representation.
 */
export const byteArrayToInt = byteArray => {
  let bigIntValue = 0n;
  for (let i = 0; i < byteArray.length; i++) {
    bigIntValue +=
      BigInt(byteArray[i]) * 256n ** BigInt(byteArray.length - 1 - i);
  }
  return bigIntValue;
};

/**
 * Convert a hexadecimal string to a BigInt.
 *
 * @param {string} str - Hexadecimal string.
 * @returns {bigint} - BigInt representation.
 */
export const bigIntFromHex = str => BigInt('0x' + str);

/**
 * Convert a BigInt to a hexadecimal string.
 *
 * @param {bigint} bigIntValue - BigInt value.
 * @returns {string} - Hexadecimal string representation.
 */
export const hexFromBigInt = bigIntValue => {
  if (typeof bigIntValue !== 'bigint') {
    throw new Error('Input must be a BigInt value');
  }

  if (bigIntValue < 0) {
    throw new Error('BigInt value cannot be negative');
  }

  return bigIntValue.toString(16);
};

/**
 * Convert an integer to an array of bytes.
 *
 * @param {number} intValue - Integer value.
 * @returns {Array<number>} - Array of bytes.
 */
export const intToByteArray = intValue => {
  const byteArray = [];

  if (intValue === 0) {
    byteArray.push(0);
    return byteArray;
  }

  const isNegative = intValue < 0;
  if (isNegative) {
    intValue = -intValue;
  }

  while (intValue > 0) {
    byteArray.unshift(Number(intValue & 0xffn));
    intValue >>= 8n;
  }

  if (isNegative) {
    byteArray.unshift(0x80); // Add a byte to indicate a negative number
  }

  return byteArray;
};

/**
 * Read a private key from a JSON file.
 *
 * @param {number} index - Index of the user's private key in the JSON file.
 * @returns {Promise<string>} - A promise that resolves to the private key as a hexadecimal string.
 * @throws {Error} - If there's an error reading the JSON file or parsing its content.
 */
export const returnPrivateKey = async index => {
  try {
    const data = await fsp.readFile('../json/users.json', 'utf8');
    const jsonData = JSON.parse(data);
    const privateKey = jsonData.users[index].privateKey;

    return privateKey;
  } catch (err) {
    console.error('Error:', err);
    throw err;
  }
};

/**
 * Convert a hexadecimal string to a BigInt.
 *
 * @param {string} hexValue - Hexadecimal string.
 * @returns {bigint} - BigInt representation.
 */
export const hexToBigInt = hexValue => {
  if (typeof hexValue !== 'string') {
    throw new Error('Input must be a string');
  }

  // Remove the "0x" prefix if present
  if (hexValue.startsWith('0x')) {
    hexValue = hexValue.slice(2);
  }

  // Ensure the remaining string is a valid hexadecimal value
  if (!/^[0-9A-Fa-f]+$/.test(hexValue)) {
    throw new Error('Input must be a valid hexadecimal string');
  }

  return BigInt('0x' + hexValue);
};

/**
 * Extract the X-coordinate from a point on the elliptic curve.
 *
 * @param {object} P - Point on the elliptic curve.
 * @returns {bigint} - X-coordinate as a BigInt.
 */
export const x = P => byteArrayToInt(P[0]);

/**
 * Extract the Y-coordinate from a point on the elliptic curve.
 *
 * @param {object} P - Point on the elliptic curve.
 * @returns {bigint} - Y-coordinate as a BigInt.
 */
export const y = P => byteArrayToInt(P[1]);

/**
 * Update a JSON file with a new object.
 *
 * @param {object} object - The object to write to the JSON file.
 * @param {string} path - The path to the JSON file.
 * @throws {Error} - If there's an error writing the JSON file.
 */
export const updateJson = (object, path) => {
  const jsonString = JSON.stringify(object, null, 2);
  fs.writeFileSync(path, jsonString);
};
