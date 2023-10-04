<br>
<p align="center">
  <img src="./images/logo.png" width="200" height="200">
</p>
<br>

# Purpose

The primary objectives of this project are as follows:

- Schnorr Key Generation and Verification: The core focus is on developing a command-line tool that facilitates the generation of cryptographic key pairs using the Schnorr algorithm. These keys can then be utilized for signing messages and verifying signatures. The tool provides the ability to generate multiple keys, create signatures, and perform signature verifications.

- Circom Integration: An integral part of the project involves implementing key verification using the Circom framework. This integration aims to demonstrate how Schnorr keys can be verified within the context of Circom's circuit language, allowing for cryptographic operations to be carried out in a verifiable manner.

- zkSNARK Proof Generation: Building upon the previous aspects, the project delves into generating zkSNARK proofs for the verification of Schnorr signatures. This phase showcases the power of zero-knowledge proofs in attesting to the validity of cryptographic operations without revealing sensitive information.

# Project Components

The project is structured as follows:

1. Schnorr Key Generation Tool
   The command-line tool (schnorr_lib.js) is designed to provide a user-friendly interface for generating cryptographic keys, signing messages, and verifying signatures using the Schnorr algorithm. The tool employs Node.js and leverages the argparse library for handling command-line options.

2. Circom Integration
   One of the pivotal components of the project involves integrating the generated Schnorr keys with the Circom framework. This entails implementing key verification within a Circom circuit, thereby showcasing the practical application of cryptographic operations within the circuit context.

3. zkSNARK Proof Generation
   The final phase of the project explores the generation of zkSNARK proofs for the verification of Schnorr signatures. By utilizing zkSNARKs, the project aims to demonstrate the ability to generate succinct proofs that verify the authenticity of Schnorr signatures without revealing private information.

## Installation

1. Clone or download this repository to your local machine.
2. Make sure you have all dependencies installed by running the following command in the project directory:

   ```bash
   npm install
   ```

## Usage

You can run the script using the following command:

```bash
node menuSchnorr.js
```

The menu will guide you through two main operations:

## Key Generation

Select "Generate keys" from the menu.
Enter the number of keys to generate.
The script will generate the keys and save them to a JSON file (users.json).

## Signature Creation

Select "Create a signature" from the menu.
Enter the message you want to sign or accept the default value.
Enter the index of the private key to use.
You can also generate JSON for Circom by selecting the corresponding option.
The signature will be created and displayed on the screen.

# Acknowledgments

This tool utilizes the Schnorr algorithm and various cryptographic operations from circomlibjs. It provides a convenient command-line interface for key generation, signature creation, and signature verification.

# License:

This project is licensed under the GPL-3.0 license. See the [LICENSE](LICENSE) file for details.

Please feel free to modify this readme according to your specific project needs and context.
