import crypto from 'crypto';
import inquirer from 'inquirer';

import { arrayBytesToHex } from './utils/utils.js';
import { generateWitness } from './test/getCircuit.js';

let isGeneratingWitness = false;
/**
 * The main function that handles user interactions and executes selected operations.
 */
async function main() {
  while (true) {
    try {
      if (!isGeneratingWitness) {
        const answers = await inquirer.prompt([
          {
            type: 'list',
            name: 'operation',
            message: 'Select operation:',
            choices: [
              'Verify and generate witness [./circuits/verifyKeySchnorrGroup.circom]',
              'Exit',
            ],
          },
        ]);

        if (answers.operation === 'Exit') {
          console.log('Bye!');
          process.exit(0);
        }

        if (
          answers.operation ===
          'Verify and generate witness [./circuits/verifyKeySchnorrGroup.circom]'
        ) {
          const messageAnswer = await inquirer.prompt([
            {
              type: 'input',
              name: 'message',
              message: 'Enter the message to sign:',
              default: () => arrayBytesToHex(crypto.randomBytes(32)),
            },
          ]);

          const numKeysAnswers = await inquirer.prompt([
            {
              type: 'number',
              name: 'number',
              message: 'Number of keys to generate:',
              default: 10,
            },
          ]);

          const privateKeyIndexAnswer = await inquirer.prompt([
            {
              type: 'number',
              name: 'index',
              message: 'Enter the index of the private key to use:',
              default: 0,
            },
          ]);

          generateWitness(
            messageAnswer.message,
            numKeysAnswers.number,
            privateKeyIndexAnswer.index
          );
          isGeneratingWitness = true;
        }
      } else {
        // Se isGeneratingWitness è true, esci dal ciclo
        break;
      }
    } catch (error) {
      console.error('An error occurred:', error);
    }
  }
}

main();
