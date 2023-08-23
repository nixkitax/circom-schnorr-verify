const fs = require("fs");
const fsp = require('fs/promises'); // Importa il modulo fs.promises

const crypto = require("crypto");
const buildBabyjub = require("circomlibjs").buildBabyjub;
const Scalar = require("ffjavascript").Scalar;

let babyJub; // Dichiarazione globale della variabile babyJub
let order;

const array_bytes_to_hex = (bytes) => {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
        ""
    );
};

const hex_to_array_bytes = (hexString) => {
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

const byte_array_to_int = (byteArray) => {
    let bigIntValue = 0n;
    for (let i = 0; i < byteArray.length; i++) {
        bigIntValue +=
            BigInt(byteArray[i]) * 256n ** BigInt(byteArray.length - 1 - i);
    }
    return bigIntValue;
};

const x = (P) => byte_array_to_int(P[0]);

const y = (P) => byte_array_to_int(P[1]);

const has_even_y = (P) => y(P) % 2n == 0n;

const big_int_from_hex = (str) => BigInt(parseInt(str, 16));

const big_int_to_hex = (bigIntValue) => {
    if (typeof bigIntValue !== 'bigint') {
        throw new Error('Input deve essere un valore BigInt');
    }

    if (bigIntValue < 0) {
        throw new Error('Il valore BigInt non può essere negativo');
    }

    return bigIntValue.toString(16);
} 

const bytes_from_int = (bigIntValue) => {
    const byteLength = 32; // Lunghezza desiderata in byte
    const byteArray = new Uint8Array(byteLength);
    
    for (let i = 0; i < byteLength; i++) {
        byteArray[byteLength - 1 - i] = Number(bigIntValue & BigInt(0xff));
        bigIntValue >>= BigInt(8);
    }
    
    return byteArray;
}


const count_bytes = (object) => {
    const byteArray = Buffer.from(object, 'hex');
    return byteArray.length;
}

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

const make_json = (object) => {
    const jsonString = JSON.stringify(object, null, 2);
    fs.writeFileSync("../json/users.json", jsonString);
    console.log("> Key pairs generated: 1 in '../json/users.json'");
};

const sign_sgnorr = (msg, privateKey) => {

    d0 = hex_to_big_int(privateKey);

    //console.log("d0 sign_sgnorr", d0);

    if (d0 > (order - 1n))  throw new Error("prvKey has to be minor than order-1 ");

    let P = babyJub.mulPointEscalar(babyJub.Base8, d0);

    const pP = babyJub.packPoint(P);
    console.log("unpacked in sign_sgnorr: ", pP);

    let d; //private key

    if (has_even_y(P)) 
        d = d0
    else 
        d = order - d0;

    //k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n

    const nonceValue = crypto.randomBytes(32);
    const hashMsg = crypto
        .createHash("sha256")
        .update("HOPE2SEEUAGA   IN")
        .digest("hex");
    const combinedHash = crypto
        .createHash("sha256")
        .update(hashMsg + nonceValue + msg)
        .digest("hex");

    const k0 = hex_to_big_int(combinedHash) % order;

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

    if (has_even_y(r)) {
        k = k0;
    } else {
        k = order - k0;
    }

    //console.log("r subgroup?", babyJub.inSubgroup(r));

    //e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n


    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(r[0] + P[0] + msg)
         .digest("hex")) % order;

    

    const LSign = bytes_from_int(x(r));

    if (big_int_from_hex(LSign) >= babyJub.p)
        console.log("R è più grande di p >:(((");


    // bytes_from_int((k + e * d) % n)

    const RSign = array_bytes_to_hex(bytes_from_int(( k + e * d) % order));
    const signature = array_bytes_to_hex(LSign) + RSign ;

    console.log(array_bytes_to_hex(LSign));

    const hashInitMsg = crypto
         .createHash("sha256")
         .update(msg)
         .digest("hex");

    console.log("> d: ", d);
    console.log("> k: ", k);
    console.log("> e: ", e);
    console.log("> msg: ", msg, "[/l: ", count_bytes(hashInitMsg), "]");
    console.log("> LSign: ", LSign, "[/l: ", count_bytes(LSign), "]");
    console.log("> RSign: ", RSign, "[/l: ", count_bytes(RSign), "]");
    console.log("> PubKey: ", array_bytes_to_hex(pP), "[/l: ", count_bytes(pP), "]" );
    console.log("> Signature: ", signature, "[/l: ", count_bytes(signature), "]");
    console.log("---------------------------------------------------------------------")
    //console.log(pP);
    if (big_int_from_hex(LSign) >= babyJub.p)
        console.log("R è più grande di p >:(((");

    verify_signature(hex_to_array_bytes(hashInitMsg), pP, hex_to_array_bytes(signature));

};

const verify_signature = (msg, packetPubkey, sig) => {

    if (msg.length !== 32) 
        throw new Error('The message must be a 32-byte array.');
   
    if (packetPubkey.length !== 32) 
        throw new Error('The public key must be a 32-byte array.');
     
    if (sig.length !== 64) 
        throw new Error('The signature must be a 64-byte array.');

    //get public key coords
    const pubKey = babyJub.unpackPoint(packetPubkey);

    console.log(sig);

    //console.log(pubKey); 

    R =sig.slice(0, 32);
    S = sig.slice(32,64);


    console.log(">R: ", R);
    console.log(">R: ", byte_array_to_int(R));

    console.log(">p: ", babyJub.p);

    console.log(">S: ", S);

    if (byte_array_to_int(R) >= babyJub.p)
        console.log("R è più grande di p ,_,");
    if (S >= babyJub.order)
        console.log("S è più grande dell'ordine ,_,")

/*
    if (P is None) or (r >= p) or (s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", get_bytes_R_from_sig(sig) + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_even_y(R)):
        # print("Please, recompute the sign. R is None or has even y")
        return False
    if x(R) != r:
        # print("There's something wrong")
        return False
    return True
    */

}

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

    const InitPrvKeyHex = array_bytes_to_hex(InitPrvKeyBytes);

    const InitPrvKeyInt = BigInt(big_int_from_hex(InitPrvKeyHex)) % order;

    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, InitPrvKeyInt);

    console.log(pubKey); 

    let prvKey;

    if (has_even_y(pubKey)) 
        prvKey = InitPrvKeyInt;
    else 
        prvKey = order - InitPrvKeyInt;

    //console.log("prvKey generation:", prvKey);

    const pPubKey = babyJub.packPoint(pubKey);
    
    //console.log("unpacked key pub in generation keys: ", pubKey);
    console.log("packed key pub in generation keys: ", array_bytes_to_hex(pPubKey));

    const pubKeyHex = array_bytes_to_hex(pPubKey);
    const prvKeyHex = big_int_to_hex(prvKey);


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

        const privateKey = await return_private_key(0); // Chiama la funzione in modo asincrono
        
        console.log('Private Key:', privateKey);
    
        sign_sgnorr(msg, privateKey);

    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();


module.exports = {
    geneterate_keys,
    //initializeBabyJub
};