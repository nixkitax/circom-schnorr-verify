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

# Installation

Before using the tool, you need to install the required Node.js packages. Open your terminal and navigate to the directory containing the project files, then run:
```
npm install
```

# Usage
The tool provides various functionalities through command-line options. Here's how you can use them:

1. Generating Keys:
To generate a specified number of cryptographic key pairs, use the -g or --generateKeys option along with the -n or --number option to specify the number of keys to generate.

```
node schnorr-lib -g -n 5
```
2. Creating Signatures: To create a signature for a message using a specific private key, use the -c or --createSignature option. You also need to provide the index of the private key to be used (-i or --index) and the message to be signed (-m or --message).

```
node schnorr-lib.js -c -i 0 -m "Message to be signed"
```
3. Verifying Signatures: To verify a signature using a given public key, signature, and original message, use the -v or --verifySign option. Provide the compressed public key (-p or --pPubKey), the signature (-s or --signature), and the original message (-orm or --originalMsg).
```
node schnorr-lib -v -p "Public Key" -s "Signature" -orm "Original Message"
```

# Command-line Options
-g, --generateKeys: Generate cryptographic key pairs.

-n, --number: Number of key pairs to generate (used with -g).

-c, --createSignature: Create a signature for a message.

-i, --index: Index of the private key to be used for signing (used with -c).

-m, --message: Message to be signed (used with -c).

-v, --verifySign: Verify a signature.

-p, --pPubKey: Compressed public key for signature verification (used with -v).

-s, --signature: Signature to be verified (used with -v).

-orm, --originalMsg: Original message for signature verification (used with -v).

## Examples

1. Generate 5 key pairs:

``` 
node schnorr_lib.js -g -n 5
```

2. Create a signature:

``` 
node schnorr_lib.js -c -i 0 -m "Message to be signed"
```

3. Verify a signature:

``` 
node schnorr_lib.js -v -p "Public Key" -s "Signature" -orm "Original Message"
```

# Future steps 
The upcoming steps for this project include:

JSON Processing for Circom Integration: The next immediate step involves processing the generated JSON data containing Schnorr keys to seamlessly integrate them into a Circom circuit. This step is crucial for demonstrating the cryptographic verification process within the circuit framework.

# Acknowledgments
This tool utilizes the Schnorr algorithm and various cryptographic operations from circomlibjs. It provides a convenient command-line interface for key generation, signature creation, and signature verification.


# License:

This project is licensed under the GPL-3.0 license. See the [LICENSE](LICENSE) file for details.

Please feel free to modify this readme according to your specific project needs and context.

