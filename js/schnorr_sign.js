const argparse = require('argparse');
const fs = require('fs');
const { printFails } = require('./utils');
const { sha256, schnorrSign, schnorrMusigSign, schnorrMusig2Sign } = require('./schnorr_lib');
const { createJson } = require('./make_json');

function main() {
    const parser = new argparse.ArgumentParser({
        description: 'returns the signature and the public key from a private key and a message'
    });
    parser.addArgument('-m', '--message', { type: 'string', required: true, help: 'Message to be signed' });
    parser.addArgument('-i', '--index', { type: 'int', help: "When single signing, by passing this argument the index of the keypair to use is specified otherwise the first will be used by default" });
    parser.addArgument('-c', '--circom', { action: 'storeTrue', help: "makes input file for the (circuit -> circom -> snarkjs)" });
    parser.addArgument('--musig1', { action: 'storeTrue', help: "Use MuSig-1" });
    parser.addArgument('--musig2', { action: 'storeTrue', help: "Use MuSig-2" });
    const args = parser.parseArgs();

    const msg = args.message;
    const circom = args.circom; // flag
    const musig1 = args.musig1; // flag
    const musig2 = args.musig2; // flag

    let i = 0; // default value for single signing
    if (args.index) {
        i = args.index;
    }

    // Get keypair
    let users;
    try {
        users = JSON.parse(fs.readFileSync("users.json", "utf8")).users;
    } catch (e) {
        printFails("[e] Error. File nonexistent, create it with create_keypair.js");
        process.exit(2);
    }

    // Signature
    try {
        // Get message digest
        const originalMess = msg;
        const M = sha256(Buffer.from(msg, 'utf8'));
        let X;
        let sig;

        if (!musig1 && !musig2) {
            if (i < 0 || i >= users.length) {
                throw new Error("Index is out of range");
            }
            sig = schnorrSign(M, users[i].privateKey);
        } else if (musig1) {
            [sig, X] = schnorrMusigSign(M, users);
        } else if (musig2) {
            [sig, X] = schnorrMusig2Sign(M, users);
        }

        if (circom) {
            try {
                users = JSON.parse(fs.readFileSync("users.json", "utf8")).users;
                const numKeys = users.length;
                const result = {
                    message: originalMess,
                    signature: sig.toString('hex'),
                    numKeys: numKeys,
                    public_keys: users.map(user => user.publicKey)
                };
                createJson(result);
            } catch (e) {
                printFails("[e] Error. File nonexistent, create it with create_keypair.js");
                process.exit(2);
            }
        }

        console.log("> Message =", originalMess);
        console.log("> NumKeys =", users.length);
        console.log("> Signature =", sig.toString('hex'));
        console.log("> Public key =", users[i].publicKey);
        if (X) {
            console.log("> Public aggregate=", X.toString('hex'));
        }
    } catch (e) {
        printFails("[e] Exception:", e);
        process.exit(2);
    }
}

if (require.main === module) {
    main();
}
