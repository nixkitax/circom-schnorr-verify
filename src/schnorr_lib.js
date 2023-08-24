const fs = require("fs");
const fsp = require('fs/promises'); // Importa il modulo fs.promises

const crypto = require("crypto");
const buildBabyjub = require("circomlibjs").buildBabyjub;
const Scalar = require("ffjavascript").Scalar;


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

const sign_shnorr = (msg, privateKey) => {

    d0 = hex_to_big_int(privateKey);

    //console.log("privateKey in schnorr", d0);

    if (d0 > babyJub.order - 1n)  throw new Error("prvKey has to be minor than order-1 ");

    let P = babyJub.mulPointEscalar(babyJub.Base8, d0);

    //console.log("unpacked in sign_sgnorr: ", P);

    let d; //private key

    if (has_even_y(P)) 
        d = d0
    else 
        d = babyJub.order - d0;

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

    const k0 = hex_to_big_int(combinedHash) % babyJub.order;
/*
    if (k0 < babyJub.order)
        console.log("k0 < babyJub.order");
    else 
        console.log("k0 > babyJub.order");
*/
    const r = babyJub.mulPointEscalar(babyJub.Base8, k0);
/*
    if (babyJub.inSubgroup(r) && babyJub.inCurve(r))
        console.log("R is good");

    else 
        console.log("R not good");
*/
    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(x(r) + x(P) + msg)
         .digest("hex"));

    const s = (k0 + d * e) % babyJub.order;

    console.log("");
    console.log("> d:    ", d);
    console.log("> k     ", k0);
    console.log("> e:    ", e);
    console.log("> x(r): ", x(r));
    console.log("> s:    ", s);
    console.log("> n:    ", babyJub.order);
    console.log("");


    const LSign = hex_from_big_int(x(r)).padStart(64, "0");
    const RSign = hex_from_big_int(s).padStart(64, "0");

    const signature = LSign + RSign;
    
    console.log("> [LSign][RSign] (bigInt): ", "\n[",big_int_from_hex(LSign),"]\n[",big_int_from_hex(RSign),"]");
    console.log("");
    console.log("> [LSign][RSign] (HEX): ", "\n[",LSign,"]\n[",RSign,"]");
    console.log("");
    console.log("> Signature: ", signature);

    verify_signature(P, msg, signature);


    /*
    console.log("x(r)", x(r));

    const LSign = x(r) % babyJub.order;

    if (LSign > babyJub.order)
        console.log("R è più grande di p >:(((");
    else    
        console.log("LSign OK!")

    console.log(LSign);
    
    console.log(hex_from_big_int(LSign));

    console.log(big_int_from_hex(LSign));

    // bytes_from_int((k + e * d) % n)

    //console.log("LSign: ", byte_array_to_int(LSign));

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
    //console.log("> LSign: ", LSign, "[/l: ", count_bytes(LSign), "]");
    console.log("> RSign: ", RSign, "[/l: ", count_bytes(RSign), "]");
    console.log("> PubKey: ", array_bytes_to_hex(pP), "[/l: ", count_bytes(pP), "]" );
    console.log("> Signature: ", signature, "[/l: ", count_bytes(signature), "]");
    console.log("---------------------------------------------------------------------")

*/
};

const verify_signature = (msg, packetPubkey, sig) => {

    if (count_bytes(sig) !== 64) 
        throw new Error('The signature must be a 64-byte array.');

    //const R,S;
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

    const InitPrvKeyInt = byte_array_to_int(InitPrvKeyBytes) % babyJub.order;

    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, InitPrvKeyInt);


    let prvKey;

    if (has_even_y(pubKey)) 
        prvKey = InitPrvKeyInt;
    else 
        prvKey = babyJub.order - InitPrvKeyInt;

    //console.log("prvKey generation:", prvKey);

    const pPubKey = babyJub.packPoint(pubKey);
   /* 
    console.log("privateKey:",prvKey, prvKey < babyJub.order);
    console.log("First generations pubKey:", pubKey); 
    console.log("packet key pub in generation keys: ", pPubKey);
    */
    const pubKeyHex = array_bytes_to_hex(pPubKey);
    const prvKeyHex = hex_from_big_int(prvKey);


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
        
        //console.log('Private Key:', privateKey);
    
        sign_shnorr(msg, privateKey);

    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();


module.exports = {
    geneterate_keys,
    //initializeBabyJub
};