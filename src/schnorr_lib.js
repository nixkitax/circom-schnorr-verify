const fs = require("fs");
const fsp = require('fs/promises');
const crypto = require("crypto");
const buildBabyjub = require("circomlibjs").buildBabyjub;
const { ArgumentParser } = require('argparse');
const { version } = require('../package.json');

(async () => {
    try {
        babyJub = await buildBabyjub();

        const F = babyJub.F;
        const order = babyJub.order;

        const parser = new ArgumentParser({
                description: 'Command-line tool for generating and verifying Schnorr cryptographic keys and signatures.'
        });

        parser.add_argument('-g', '--generateKeys', { action: "store_true", help: 'Generate keys' });
        parser.add_argument('-n', '--number', { type: Number, help: 'Number of keys to generate', required: false ,  default: 1 });
        parser.add_argument('-c', '--createSignature', { action: "store_true", help: 'creation of a signature', required: false});
        parser.add_argument('-i', '--index', { type: Number, help: 'index of a privateKey', required: false, default: 0});
        parser.add_argument('-m', '--message', { type: String, help: 'Message to sign', required: false, default: array_bytes_to_hex(crypto.randomBytes(32)) });
        parser.add_argument('-v', '--verifySign', { action: "store_true", help: 'message to sign', required: false  });
        parser.add_argument('-p', '--pPubKey', { type: String, help: 'publicKey to verify a signature', required: false, default: " "  });
        parser.add_argument('-s', '--signature', { type: String, help: 'signature to verify', required: false, default: " "  });
        parser.add_argument('-orm', '--originalMsg', { type: String, help: 'original message to verify', required: false, default: " "  });

        const args = parser.parse_args();
        if (args.generateKeys) generate_keys(args.number);
        if (args.createSignature){ 
            const privateKey = await return_private_key(args.index);
            sign_schnorr(args.message, privateKey, "sign");
        }
        if(args.verifySign){
            if(args.pPubKey == " ") console.error("You have to insert a compressed public key [HEX] to verify a signature, node schnorr.js -h");
            if(args.signature == " ") console.error("You have to insert a signature [HEX] to verify a signature, node schnorr.js -h");
            if(args.originalMsg == " ") console.error("You have to insert the original message to verify a signature, node schnorr.js -h");
            //console.log(args.originalMsg);
            verify_signature(args.pPubKey, args.originalMsg, args.signature, "verify");
        }

    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();

const array_bytes_to_hex = (bytes) => {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
        ""
    );
};

const hex_to_array_bytes = (hexString) => {
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return bytes;
};

const x = (P) => byte_array_to_int(P[0]);

const y = (P) => byte_array_to_int(P[1]);

const byte_array_to_int = (byteArray) => {
    let bigIntValue = 0n;
    for (let i = 0; i < byteArray.length; i++) {
        bigIntValue +=
            BigInt(byteArray[i]) * 256n ** BigInt(byteArray.length - 1 - i);
    }
    return bigIntValue;
};

const has_even_y = (P) => y(P) % 2n == 0n;

const big_int_from_hex = (str) => BigInt('0x' + str);

const hex_from_big_int = (bigIntValue) => {
    if (typeof bigIntValue !== 'bigint') {
        throw new Error('Input deve essere un valore BigInt');
    }

    if (bigIntValue < 0) {
        throw new Error('Il valore BigInt non può essere negativo');
    }

    return bigIntValue.toString(16);
} 

const int_to_byte_array = (intValue) => {
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

const hex_to_big_int = (hexValue) => {
  
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
}


const return_private_key = async (index) => {
    try {
        const data = await fsp.readFile('../json/users.json', 'utf8'); // Utilizza await per aspettare la lettura del file
        const jsonData = JSON.parse(data);
        const privateKey = jsonData.users[0].privateKey;

        return privateKey; // Restituisce la chiave privata
    } catch (err) {
        console.error('Errore:', err);
        throw err; // Rilancia l'errore per gestirlo al livello superiore
    }
};


const return_public_key = async (index) => {
    try {
        const data = await fsp.readFile('../json/users.json', 'utf8'); // Utilizza await per aspettare la lettura del file
        const jsonData = JSON.parse(data);
        const publicKey = jsonData.users[0].publicKey;

        return publicKey; // Restituisce la chiave privata
    } catch (err) {
        console.error('Errore:', err);
        throw err; // Rilancia l'errore per gestirlo al livello superiore
    }
};

const verify_key_pair = (msg, prvKeyHex) => {

    return sign_schnorr(msg, prvKeyHex, "verKey");

}

const update_users_json = (object, path) => {
    const jsonString = JSON.stringify(object, null, 2);
    fs.writeFileSync(path, jsonString);
};

const sign_schnorr = (msg, privateKey, type) => {

    d0 = hex_to_big_int(privateKey);

    if (d0 > babyJub.order - 1n)  throw new Error("prvKey has to be minor than order-1 ");

    let P = babyJub.mulPointEscalar(babyJub.Base8, d0);

    let d; //private key

    if (has_even_y(P)) 
        d = d0
    else 
        d = babyJub.order - d0;

    const nonceValue = crypto.randomBytes(32);
    const hashMsg = crypto
        .createHash("sha256")
        .update("HOPE2SEEUAGA")
        .digest("hex");
    const combinedHash = crypto
        .createHash("sha256")
        .update(hashMsg + nonceValue + msg)
        .digest("hex");

    const k0 = (hex_to_big_int(combinedHash))% babyJub.order;

    const r = babyJub.mulPointEscalar(babyJub.Base8, k0);

    const concatHash = hex_from_big_int(x(r)) + hex_from_big_int(x(P)) + msg;

    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(concatHash)
         .digest("hex")) % babyJub.order;
    const LSign = hex_from_big_int(x(r));
    const RSign = hex_from_big_int((k0 + d * e) % babyJub.order);
    const pPubKey = babyJub.packPoint(P);
    const signature = LSign.concat(RSign);

    switch(type){
        case "verKey": 
            return verify_signature(pPubKey, msg, signature, "verKey");
        case "sign": 
            console.log("");
            console.log("> [Sign_Schnorr] d:                       ", d);
            console.log("> [Sign_Schnorr] k                        ", k0);
            console.log("> [Sign_Schnorr] e:                       ", e);
            console.log("> [Sign_Schnorr] x(r):                    ", x(r));
            console.log("> [Sign_Schnorr] n:                       ", babyJub.order);
            console.log("");
            console.log("> [Sign_Schnorr][LSign][RSign] (bigInt): ", "\n\n\t   [",big_int_from_hex(LSign),"]\n\t   [",big_int_from_hex(RSign),"]\n");
            console.log("> [Sign_Schnorr]([LSign][RSign]) (HEX): ", "\n\n\t   [",LSign + RSign,"]\n");
            console.log("> [Sign_Schnorr] message:      ", msg);
            console.log("> [Sign_Schnorr] public key:   ", array_bytes_to_hex(pPubKey) )
            console.log("");
            //console.log( hex_to_array_bytes(array_bytes_to_hex(pPubKey)))
            //return verify_signature(pPubKey, msg, signature, "verify");
            break;
        case "default":
            console.error("There is unknown paramaters for schnorr_sign");
    }
    
};

const verify_signature = (pPubKey, msg, signature, type) => {

    if(type == "verify")
        pPubKey = hex_to_array_bytes(pPubKey);

    //console.log("msg", msg);
    let P = babyJub.unpackPoint(pPubKey);
    let isOK;
    const LSign = signature.slice(0, 64);
    const RSign = signature.slice(64);
    const R = big_int_from_hex(LSign); 
    const s = big_int_from_hex(RSign) 
    const concatHash = LSign + hex_from_big_int(x(P)) + msg;
    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(concatHash)
         .digest("hex")) % babyJub.order;
    const gs = babyJub.mulPointEscalar(babyJub.Base8, s);
    const Pe = babyJub.mulPointEscalar(P, babyJub.order - e);
    const newR = babyJub.addPoint(gs, Pe);
    if(R == x(newR)) isOK = true;

    switch(type){
            case "verKey": 
                if(isOK) 
                    return true;
                else break;
            case "verify": 
                console.log("> [Verify_signature] R:                  ", R);
                console.log("> [Verify_signature] xnewPoint:          ", x(newR));
                if(isOK) console.log("\n\t\t\t\t\t  Verification is OK :)");
                break;
            case "default":
                console.error("There is unknown paramaters for schnorr_sign");
    }
}

const generate_keys = (numKeys) => {

    console.log("> [Generation Key] Generating","[", numKeys,"]", "in \"../json/users.json");
    let count = 0;
    let object = {
        $schema: "./users_schema.json",
        users: [],
    };
    
    while(count < numKeys){

            const InitPrvKeyBytes = crypto.randomBytes(32);
            const InitPrvKeyInt = byte_array_to_int(InitPrvKeyBytes) % babyJub.order;
            const pubKey = babyJub.mulPointEscalar(babyJub.Base8, InitPrvKeyInt);
            let prvKey;
            if (has_even_y(pubKey)) 
                prvKey = InitPrvKeyInt;
            else 
                prvKey = babyJub.order - InitPrvKeyInt;
            const pPubKey = babyJub.packPoint(pubKey);
            const pubKeyHex = array_bytes_to_hex(pPubKey);
            const prvKeyHex = hex_from_big_int(prvKey);
            const msg = array_bytes_to_hex(crypto.randomBytes(32));

            const isKeyGood = verify_key_pair(msg, prvKeyHex, "verKey");           
            if (isKeyGood) {
                object.users.push({ publicKey: pubKeyHex, privateKey: prvKeyHex });
                count++;
            }
    }
    
    console.log("> [Generation Key] Created","   [", numKeys,"]", "in \"../json/users.json");
    update_users_json(object, "../json/users.json");
};




module.exports = {
    generate_keys,
    //initializeBabyJub
};