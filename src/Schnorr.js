const fs = require('fs')
const crypto = require("crypto");
const { c } = require('circom_tester');
const buildEddsa = require("circomlibjs").buildEddsa; //babyjubjub, poseidon, OK!
const buildBabyjub = require("circomlibjs").buildBabyjub;
const Scalar = require("ffjavascript").Scalar;

const buffer2bits = (buff) => {
    const res = [];
    for (let i = 0; i < buff.length; i++) {
        for (let j = 0; j < 8; j++) {
            if ((buff[i] >> j) & 1) {
                res.push(1n);
            } else {
                res.push(0n);
            }
        }
    }
    return res;
}

const ArrayBytesToHex = (bytes)  => {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
const fromHexString = hexString =>
    new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const toHexString = bytes =>
    bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

const x = (P) => P[0];

const y = (P) => P[1]; 

const hasEvenY = (P) =>  (P[1] % 2 ) == 0;

const int_from_hex = (str) => parseInt(str, 16);

const signSchnorr = (msg, privateKey) => {

    d0 = BigInt(int_from_hex(privateKey));

    if(d0 > order  )
        console.log("prvKey has to be minor that order-1 "); 
    
    const P = babyJub.mulPointEscalar(babyJub.Base8, d0);
    let d;
   
    if(hasEvenY(P)) 
        d = d0;
    else
        d = order - d0;

    console.log(pubKey[1]);
    console.log(pubKey[1] % 2);
    console.log("d0: " + d0);
    console.log("d: "+ d);
    
    //k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n

    const nonceValueInt = parseInt(crypto.randomBytes(32).toString('hex'), 16);
    const hashMsg = crypto.createHash('sha256').update("HOPE2SEEUAGAIN").digest('hex');
    const combinedHash = crypto.createHash('sha256').update(hashMsg + nonceValueInt.toString() ).digest('hex');
    
    const k0 = BigInt(parseInt(combinedHash, 16)) % order ;

    console.log(">k0: " + k0);

     
    /*
    console.log("Nonce:", nonceValueInt.toString());
    console.log("Hash del messaggio:", hashMsg);
    console.log("Hash combinato:", combinedHash);
    */

    const r = babyJub.mulPointEscalar(babyJub.Base8, k0);

    //k = n - k0 if not has_even_y(R) else k0

    let k;

    if (!hasEvenY(r)) {
        k = order - k0;
    } else {
        k = k0;
    }

    console.log("r subgroup?", babyJub.inSubgroup(r));

    const e = crypto.createHash('sha256').update(r[0] + msg).digest('hex');

    

    const LSign = ArrayBytesToHex(r[0]);


    console.log("> k: ", k);
    console.log("> e: ", e);
    console.log("> LSign: ", LSign);

    console.log("order babyjubjub: ", babyJub.order);

} 

(async () => {
    try {
        eddsa = await buildEddsa();
        babyJub = await buildBabyjub();
        
        F = babyJub.F;
        order = babyJub.order;

        const msg = "hello";
        
        const prvKey = crypto.randomBytes(32);

        const prvKeyInt = BigInt(`0x${prvKey.toString("hex")}`) % order ;


        const prvKeyHex = prvKeyInt.toString(16);

        const pubKey = babyJub.mulPointEscalar(babyJub.Base8, prvKeyInt);


        const pPubKey =  babyJub.packPoint(pubKey);

        const pubKeyHex = ArrayBytesToHex(pPubKey);


        let pair = {
            "privateKey": prvKeyHex,
            "publicKey": pubKeyHex
        };

        let object = {
            "$schema": "./users_schema.json",
            "users": [
                
            ]
        };

        object.users.push(pair);

        console.log(object);

        signSchnorr(msg, prvKeyHex);

    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();
