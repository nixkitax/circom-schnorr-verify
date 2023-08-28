const fs = require("fs");
const fsp = require('fs/promises'); // Importa il modulo fs.promises

const crypto = require("crypto");
const buildBabyjub = require("circomlibjs").buildBabyjub;
const Scalar = require("ffjavascript").Scalar;

let count = 0;

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

const make_json = (object, path) => {
    const jsonString = JSON.stringify(object, null, 2);
    fs.writeFileSync(path, jsonString);
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

    //console.log("d in sign:",d);
    //k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n

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

    if (k0 < babyJub.p)
        console.log("k0 < babyJub.p");
    else 
        console.log("k0 > babyJub.p");

    const r = babyJub.mulPointEscalar(babyJub.Base8, k0);

    if (babyJub.inSubgroup(r) && babyJub.inCurve(r))
        console.log("R is good");

    else 
        console.log("R not good");

    const concatHash = hex_from_big_int(x(r)) + hex_from_big_int(x(P)) + msg;

    console.log("elementi hash", hex_from_big_int(x(r)) + hex_from_big_int(x(P)) + msg);


    //console.log("x(r)",x(r));

    console.log("hash concatenato:", concatHash);

    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(concatHash)
         .digest("hex")) % babyJub.order;
 
    console.log("");
    console.log("> [Sign_Schnorr] d:                       ", d);
    console.log("> [Sign_Schnorr] k                        ", k0);
    console.log("> [Sign_Schnorr] e:                       ", e);
    console.log("> [Sign_Schnorr] x(r):                    ", x(r));
    console.log("> [Sign_Schnorr] n:                       ", babyJub.order);
    console.log("");

    const LSign = hex_from_big_int(x(r));
    const RSign = hex_from_big_int((k0 + d * e) % babyJub.order);

    const signature = LSign.concat(RSign);
    
    console.log("> [Sign_Schnorr][LSign][RSign] (bigInt): ", "\n\t\t\t\t\t  [",big_int_from_hex(LSign),"]\n\t\t\t\t\t  [",big_int_from_hex(RSign),"]");
    console.log("");
    console.log("> [Sign_Schnorr]([LSign][RSign]) (HEX): ", "\n\t\t\t\t\t  [",LSign,"]\n\t\t\t\t\t  [",RSign,"]");
    console.log("");
    
    verify_signature(P, msg, signature);
};

const fix_pub_key = (P) => {
    if(y(P) % 2n == 0n){
        console.log(babyJub.p - y(P));
        console.log(bytes_from_int(babyJub.p - y(P)));
        console.log(byte_array_to_int(bytes_from_int(babyJub.p - y(P))));

     }

    if(P == null) 
        return null;
    if(y(P) % 2n == 0n)
        P[1] = bytes_from_int(y(P));
    else
        P[1] = bytes_from_int(babyJub.p - y(P));
}

const verify_signature = (P, msg, signature) => {
/*
    if(y(P) % 2 == 0)
         y(P)
    else 
        babyJub.p - y(P);
*/
    //fix_pub_key(P);  
    
    if(!(y(P) % 2n == 0n))
         console.log("ouch");

    const LSign = signature.slice(0, 64);
    const RSign = signature.slice(64);

    const R = big_int_from_hex(LSign); // Convert HEX to BigInt
    const s = big_int_from_hex(RSign) // Convert HEX to BigInt

    console.log("> [Verify_signature] s [BigInt/RSign]:   ",s);

    const concatHash = LSign + hex_from_big_int(x(P)) + msg;

    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(concatHash)
         .digest("hex")) % babyJub.order;
 
    console.log("> [Verify_signature] e :                 ", e);

    const gs = babyJub.mulPointEscalar(babyJub.Base8, s);
    const Pe = babyJub.mulPointEscalar(P, babyJub.order - e);

    //console.log("> gs: ", gs);
    //console.log("> Pe: ", Pe);

    const newR = babyJub.addPoint(gs, Pe);

    //console.log("> new Point: ", newR);
    console.log("");
    
    console.log("> [Verify_signature] R:                  ", R);
    console.log("> [Verify_signature] xnewPoint:          ", x(newR));

    if(R == x(newR)){
        console.log("\n\t\t\t\t\t  Verification is OK :)");
    }

}

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

    make_json(object, "../json/users.json");
    console.log("> Key pairs generated: 1 in '../json/users.json'");

};

(async () => {
    try {
        babyJub = await buildBabyjub();

        F = babyJub.F;
        order = babyJub.order;

        const msg = "hello";

        

        const privateKey = await return_private_key(0); // Chiama la funzione in modo asincrono
        
        //console.log('Private Key:', privateKey);
        geneterate_keys();
        sign_shnorr(msg, privateKey);

    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();


module.exports = {
    geneterate_keys,
    //initializeBabyJub
};