<br>
<p align="center">
  <img src="./images/logo.png" width="200" height="200">
</p>
<br>

# circom-schnorr-verify
The "circom-schnorr-verify" project aims to create a cryptographically secure proof using the circom library and zk-SNARK technology to verify the statement "I know a Schnorr signature associated with a public key belonging to a group with at least two public keys." The proof leverages the power of zero-knowledge proofs to demonstrate knowledge of a Schnorr signature without revealing any sensitive information.

## Installation

Before using the tool, you need to install the required Node.js packages. Open your terminal and navigate to the directory containing the project files, then run:
```
npm install

```

## Usage
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

## Command-line Options
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
node schnorr.js -g -n 5
```

2. Create a signature:

``` 
node schnorr.js -c -i 0 -m "Message to be signed"

```

3. Verify a signature:

``` 
node schnorr.js -v -p "Public Key" -s "Signature" -orm "Original Message"

```


## Acknowledgments
This tool utilizes the Schnorr algorithm and various cryptographic operations from circomlibjs. It provides a convenient command-line interface for key generation, signature creation, and signature verification.


# License:

This project is licensed under the GPL-3.0 license. See the [LICENSE](LICENSE) file for details.

Please feel free to modify this readme according to your specific project needs and context.

