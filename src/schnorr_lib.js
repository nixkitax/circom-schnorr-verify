const fs = require("fs");
const fsp = require('fs/promises'); // Importa il modulo fs.promises

const crypto = require("crypto");
const buildBabyjub = require("circomlibjs").buildBabyjub;
const Scalar = require("ffjavascript").Scalar;

let babyJub; // Dichiarazione globale della variabile babyJub
let order;

const ArrayBytesToHex = (bytes) => {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
        ""
    );
};

const hexToArrayBytes = (hexString) => {
    if (hexString.length % 2 !== 0) {
        throw new Error("has to be even the string ");
    }

    const byteLength = hexString.length / 2;
    const byteArray = new Uint8Array(byteLength);

    for (let i = 0; i < byteLength; i++) {
        const byteHex = hexString.substr(i * 2, 2);
        byteArray[i] = parseInt(byteHex, 16);
    }

    return byteArray;
};

const byteArrayToInt = (byteArray) => {
    let bigIntValue = 0n;
    for (let i = 0; i < byteArray.length; i++) {
        bigIntValue +=
            BigInt(byteArray[i]) * 256n ** BigInt(byteArray.length - 1 - i);
    }
    return bigIntValue;
};

const x = (P) => byteArrayToInt(P[0]);

const y = (P) => byteArrayToInt(P[1]);

const hasEvenY = (P) => y(P) % 2n == 0n;

const int_from_hex = (str) => parseInt(str, 16);

const bigIntToHex = (bigIntValue) => {
    if (typeof bigIntValue !== 'bigint') {
        throw new Error('Input deve essere un valore BigInt');
    }

    if (bigIntValue < 0) {
        throw new Error('Il valore BigInt non può essere negativo');
    }

    return bigIntValue.toString(16);
} 

const hexToBigInt = (hexValue) => {
  
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


const returnPrivKey = async (index) => {
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

const make_json = (object) => {
    const jsonString = JSON.stringify(object, null, 2);
    fs.writeFileSync("../json/users.json", jsonString);
    console.log("> Key pairs generated: 1 in '../json/users.json'");
};

const signSchnorr = (msg, privateKey) => {

    d0 = hexToBigInt(privateKey);

    //console.log("d0 signSchnorr", d0);

    if (d0 > (order - 1n))  throw new Error("prvKey has to be minor than order-1 ");

    let P = babyJub.mulPointEscalar(babyJub.Base8, d0);

    //console.log("unpacked in SignSchnorr: ", P);

    let d; //private key

    if (hasEvenY(P)) 
        d = d0
    else 
        d = order - d0;

    //k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n

    const nonceValue = crypto.randomBytes(32);
    const hashMsg = crypto
        .createHash("sha256")
        .update("HOPE2SEEUAGAIN")
        .digest("hex");
    const combinedHash = crypto
        .createHash("sha256")
        .update(hashMsg + nonceValue + msg)
        .digest("hex");

    const k0 = hexToBigInt(combinedHash) % order;

    //console.log("> k0: " + k0);

    /*
    console.log("Nonce:", nonceValueInt.toString());
    console.log("Hash del messaggio:", hashMsg);
    console.log("Hash combinato:", combinedHash);
    */

    const r = babyJub.mulPointEscalar(babyJub.Base8, k0);

    //k = n - k0 if not has_even_y(R) else k0
    //console.log(r);

    let k;

    if (hasEvenY(r)) {
        k = k0;
    } else {
        k = order - k0;
    }

    //console.log("r subgroup?", babyJub.inSubgroup(r));

    //e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n


    const e = hexToBigInt(crypto
         .createHash("sha256")
         .update(r[0] + P[0] + msg)
         .digest("hex")) % order;

    
    const LSign = ArrayBytesToHex(r[0]);

    // bytes_from_int((k + e * d) % n)

    const RSign = bigIntToHex(( k + e * d) % order);
    const signature = LSign.concat(RSign);


    console.log("> d: ", d);
    console.log("> k: ", k);
    console.log("> e: ", e);
    console.log("> msg: ", msg);
    console.log("> LSign: ", LSign);
    console.log("> RSign: ", RSign);

    console.log("> Signature: ", signature);
};

/*
const initializeBabyJub = async () => {
    if (!babyJub) {
        babyJub = await buildBabyJub();
    }

    F = babyJub.F;
    order = babyJub.order;

    return babyJub; // Restituisci il valore di order dalla funzione
};
*/

const geneterate_keys = () => {

    const InitPrvKeyBytes = crypto.randomBytes(32);

    const InitPrvKeyHex = ArrayBytesToHex(InitPrvKeyBytes);

    const InitPrvKeyInt = BigInt(int_from_hex(InitPrvKeyHex)) % order;

    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, InitPrvKeyInt);

    let prvKey;

    if (hasEvenY(pubKey)) 
        prvKey = InitPrvKeyInt;
    else 
        prvKey = order - InitPrvKeyInt;

    //console.log("prvKey generation:", prvKey);

    const pPubKey = babyJub.packPoint(pubKey);
    
    //console.log("unpacked key pub in generation keys: ", pubKey);
    //console.log("packed key pub in generation keys: ", pPubKey);


    const pubKeyHex = ArrayBytesToHex(pPubKey);
    const prvKeyHex = bigIntToHex(prvKey);


    let pair = {
        publicKey: pubKeyHex,
        privateKey: prvKeyHex,
    };

    let object = {
        $schema: "./users_schema.json",
        users: [],
    };

    object.users.push(pair);

    make_json(object);
};

(async () => {
    try {
        babyJub = await buildBabyjub();

        F = babyJub.F;
        order = babyJub.order;

        const msg = "hello";

        geneterate_keys();

        const privateKey = await returnPrivKey(0); // Chiama la funzione in modo asincrono
        
        console.log('Private Key:', privateKey);
    
        signSchnorr(msg, privateKey);

    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();


module.exports = {
    geneterate_keys,
    //initializeBabyJub
};