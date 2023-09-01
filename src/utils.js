import fs from 'fs';
import fsp from 'fs/promises';

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
    throw new Error('Input deve essere un valore BigInt');
  }

  if (bigIntValue < 0) {
    throw new Error('Il valore BigInt non può essere negativo');
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
    byteArray.unshift(0x80); // Aggiunge un byte per segnalare il numero negativo
  }

  return byteArray;
};

export const returnPrivateKey = async index => {
  try {
    const data = await fsp.readFile('../json/users.json', 'utf8'); // Utilizza await per aspettare la lettura del file
    const jsonData = JSON.parse(data);
    const privateKey = jsonData.users[index].privateKey;

    return privateKey; // Restituisce la chiave privata
  } catch (err) {
    console.error('Errore:', err);
    throw err; // Rilancia l'errore per gestirlo al livello superiore
  }
};

export const hexToBigInt = hexValue => {
  if (typeof hexValue !== 'string') {
    throw new Error('Input deve essere una stringa');
  }

  // Rimuoviamo il prefisso "0x" se presente
  if (hexValue.startsWith('0x')) {
    hexValue = hexValue.slice(2);
  }

  // Verifichiamo che la stringa rimanente sia un valore esadecimale valido
  if (!/^[0-9A-Fa-f]+$/.test(hexValue)) {
    throw new Error('Input deve essere una stringa esadecimale valida');
  }

  return BigInt('0x' + hexValue);
};

export const x = P => byteArrayToInt(P[0]);

export const y = P => byteArrayToInt(P[1]);

export const updateJson = (object, path) => {
  const jsonString = JSON.stringify(object, null, 2);
  fs.writeFileSync(path, jsonString);
};
