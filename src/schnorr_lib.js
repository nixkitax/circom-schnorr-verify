const fs = require("fs");
const fsp = require('fs/promises'); // Importa il modulo fs.promises
const assert = require('assert');
const crypto = require("crypto");
const { emitWarning } = require("process");
const buildBabyjub = require("circomlibjs").buildBabyjub;
const Scalar = require("ffjavascript").Scalar;



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

const array_bytes_to_hex = (bytes) => {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
        ""
    );
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

const stringToBytes32 = (inputString) => {
  // Converti la stringa in un array di byte usando TextEncoder
  const textEncoder = new TextEncoder();
  const stringBytes = textEncoder.encode(inputString);

  // Padding con zeri se la lunghezza è inferiore a 32 byte
  const paddedBytes = new Uint8Array(32).fill(0);
  paddedBytes.set(stringBytes, 0);

  // Se la lunghezza è superiore a 32 byte, taglia l'array
  if (stringBytes.length > 32) {
    return paddedBytes.slice(0, 32);
  }

  return paddedBytes;
}

const make_json = (object) => {
    const jsonString = JSON.stringify(object, null, 2);
    fs.writeFileSync("../json/users.json", jsonString);
    console.log("> Key pairs generated: 1 in '../json/users.json'");
};

const sign_shnorr = (msg, privateKey) => {
    
    let d;

    if (msg.length != 32) throw new Error("The message must be a 32-byte array");
    d0 = hex_to_big_int(privateKey);
    if (d0 > babyJub.order - 1n || d0 <= 1n )  throw new Error("prvKey has to be minor than order-1 ");
    const P = babyJub.mulPointEscalar(babyJub.Base8, d0);
    has_even_y(P) ?  d = d0 : d = babyJub.order - d0;
    const combinedHash = crypto
        .createHash("sha256")
        .update("HOPE2SEEUAGAIN" + crypto.randomBytes(32) + msg)
        .digest("hex");
    const k0 = hex_to_big_int(combinedHash) % babyJub.order;
    if (k0 == 0)  throw new Error("This can happen if combinedHash == order [negligible probability] ");
    const r = babyJub.mulPointEscalar(babyJub.Base8, k0);
    const k = !has_even_y(r) ? babyJub.order - k0 : k0;
    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(hex_from_big_int(x(r)) + hex_from_big_int(x(P)) + msg)
         .digest("hex")) % babyJub.order;
 
    console.log("");
    console.log("> d:    ", d);
    console.log("> k     ", k);
    console.log("> e:    ", e);
    console.log("> x(r): ", x(r));
    console.log("> n:    ", babyJub.order);
    console.log("");

    const LSign = hex_from_big_int(x(r)).padStart(64, "0");
    const RSign = hex_from_big_int((k + d * e) % babyJub.order).padStart(64, "0");

    const signature = LSign.concat(RSign);
    
    console.log("> [LSign][RSign] (bigInt): ", "\n[",big_int_from_hex(LSign),"]\n[",big_int_from_hex(RSign),"]");
    console.log("");
    console.log("> [LSign][RSign] (HEX): ", "\n[",LSign,"]\n[",RSign,"]");
    console.log("");
    console.log("> Signature: ", signature);

    verify_signature(P, msg, signature);
};

const verify_signature = (P, msg, signature) => {

    const LSign = signature.slice(0, 64);
    const RSign = signature.slice(64);

    const R = big_int_from_hex(LSign); 
    const s = big_int_from_hex(RSign) 

    console.log("> R [BigInt/LSign]: ",R, "[ Is it okay? (?R<p): ", R < babyJub.p, "]");
    console.log("> S [BigInt/LSign]: ",s, "[ Is it okay? (?s<order): ", s < babyJub.order, "]");

    const concatHash = LSign + hex_from_big_int(x(P)) + msg;

    const e = hex_to_big_int(crypto
         .createHash("sha256")
         .update(concatHash)
         .digest("hex")) % babyJub.order;

    console.log("> e:                ", e);

    const gs = babyJub.mulPointEscalar(babyJub.Base8, s);
    const Pe = babyJub.mulPointEscalar(P, order - e);

    //console.log("> gs: ", gs);
    //console.log("> Pe: ", Pe);

    const newR = babyJub.addPoint(gs, Pe);

    //console.log("> new Point: ", newR);

    console.log("Is newR totally okay?:", has_even_y(newR));
    
    console.log("> R:", R);
    console.log("> xnewPoint", x(newR));

}

const geneterate_keys = () => {

    const InitPrvKeyBytes = crypto.randomBytes(32);
    const InitPrvKeyInt = byte_array_to_int(InitPrvKeyBytes) % babyJub.order;
    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, InitPrvKeyInt);

    let prvKey;

    prvKey = has_even_y(pubKey) ? InitPrvKeyInt :  babyJub.order - InitPrvKeyInt;

    const pPubKey = babyJub.packPoint(pubKey);
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

        //geneterate_keys();

        const privateKey = await return_private_key(0); // Chiama la funzione in modo asincrono
            
        sign_shnorr(stringToBytes32(msg), privateKey);

        
    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();


module.exports = {
    geneterate_keys,
    //initializeBabyJub
};