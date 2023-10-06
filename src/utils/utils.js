import fs from 'fs';
import fsp from 'fs/promises';
import crypto from 'crypto';
import { exec } from 'child_process';

export const hasEvenY = P => y(P) % 2n == 0n;

export const arrayBytesToHex = bytes => {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
};

export const hexToArrayBytes = hexString => {
  const bytes = [];
  for (let i = 0; i < hexString.length; i += 2) {
    bytes.push(parseInt(hexString.substr(i, 2), 16));
  }
  return bytes;
};
export const byteArrayToInt = byteArray => {
  let bigIntValue = 0n;
  for (let i = 0; i < byteArray.length; i++) {
    bigIntValue +=
      BigInt(byteArray[i]) * 256n ** BigInt(byteArray.length - 1 - i);
  }
  return bigIntValue;
};

export const bigIntFromHex = str => BigInt('0x' + str);

export const hexFromBigInt = bigIntValue => {
  if (typeof bigIntValue !== 'bigint') {
    throw new Error('Input must be a BigInt value');
  }

  if (bigIntValue < 0) {
    throw new Error('BigInt value cannot be negative');
  }

  return bigIntValue.toString(16);
};

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

export const x = P => byteArrayToInt(P[0]);

export const y = P => byteArrayToInt(P[1]);

export const updateJson = (object, path) => {
  const jsonString = JSON.stringify(object, null, 2);
  fs.writeFileSync(path, jsonString);
};

export const stringToBigInt = input => {
  const hash = crypto.createHash('sha256').update(input).digest('hex');
  return BigInt(`0x${hash}`);
};

export const generateRandomBigInt = maxBits => {
  const words = Math.ceil(maxBits / 32);
  const arr = new Uint32Array(words);
  crypto.getRandomValues(arr);
  const excessBits = words * 32 - maxBits;
  if (excessBits > 0) {
    const mask = (1 << (32 - excessBits)) - 1;
    arr[words - 1] &= mask;
  }
  return BigInt(arr.join(''));
};

export const getR1CSInfo = circuitName => {
  exec(`circom test/circuits/${circuitName} --r1cs `, (error, stdout) => {
    if (error) {
      console.error(
        `Errore durante l'esecuzione del comando: ${error.message}`
      );
      return;
    }
    console.log(`${stdout}`);
  });
};
