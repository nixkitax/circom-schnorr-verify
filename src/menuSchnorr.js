import crypto from 'crypto';
import fs from 'fs';
import inquirer from 'inquirer';

import { arrayBytesToHex, returnPrivateKey } from './utils.js';
import { generateKeys } from './generateKeys.js';
import { signSchnorr } from './signShnorr.js';

(async () => {
  try {
    const answers = await inquirer.prompt([
      {
        type: 'list',
        name: 'operation',
        message: 'Select operation:',
        choices: ['Generate keys', 'Create a signature'],
      },
    ]);

    if (answers.operation === 'Generate keys') {
      const numKeysAnswers = await inquirer.prompt([
        {
          type: 'number',
          name: 'number',
          message: 'Number of keys to generate:',
          default: 1,
        },
      ]);

      generateKeys(numKeysAnswers.number);
    } else if (answers.operation === 'Create a signature') {
      const signatureAnswers = await inquirer.prompt([
        {
          type: 'input',
          name: 'message',
          message: 'Enter the message to sign:',
          default: () => arrayBytesToHex(crypto.randomBytes(32)),
        },
        {
          type: 'number',
          name: 'index',
          message: 'Enter the index of the private key to use:',
          default: 0,
        },
        {
          type: 'confirm',
          name: 'circomJSON',
          message: 'Generate JSON for circom?',
          default: false,
        },
      ]);

      if (fs.existsSync('../json/users.json')) {
        const jsonData = JSON.parse(
          fs.readFileSync('../json/users.json', 'utf8')
        );
        const numberOfPublicKeys = jsonData.users.length;

        if (
          signatureAnswers.index >= numberOfPublicKeys ||
          signatureAnswers.index < 0
        ) {
          console.error(
            '> Error in execution: Index is out of bounds. There are',
            numberOfPublicKeys,
            'keys in users.json (indices: 0 to',
            numberOfPublicKeys - 1,
            ')'
          );
          process.exit(1);
        }

        const privateKey = await returnPrivateKey(signatureAnswers.index);

        if (signatureAnswers.circomJSON) {
          signSchnorr(signatureAnswers.message, privateKey, 'signC');
        } else {
          signSchnorr(signatureAnswers.message, privateKey, 'sign');
        }
      } else {
        console.error(
          `> Error in execution: You have to generate your keys with: node schnorr_lib.js -g -n numKeys, look at https://github.com/lyylaaa/circom-schnorr-verify`
        );
        process.exit(1);
      }
    }
  } catch (error) {
    console.error('Si è verificato un errore:', error);
  }
})();
