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

const hexToArrayBytes = (hexString)  => {
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
}

const byteArrayToInt = (byteArray) => {
  let bigIntValue = 0n;
  for (let i = 0; i < byteArray.length; i++) {
    bigIntValue += BigInt(byteArray[i]) * (256n ** BigInt(byteArray.length - 1 - i));
  }
  return bigIntValue;
}

const x = (P) => byteArrayToInt(P[0]);

const y = (P) => byteArrayToInt(P[1]); 

const hasEvenY = (P) =>  (y(P) % 2n ) == 0n;

const int_from_hex = (str) => parseInt(str, 16);

const signSchnorr = (msg, privateKey) => {

    d0 = BigInt(int_from_hex(privateKey));

    if( d0 > order - 1n)
        console.log("prvKey has to be minor that order-1 "); 
    
    let P = babyJub.mulPointEscalar(babyJub.Base8, d0);

    const pPubKey =  babyJub.packPoint(P);

    console.log("key pub: ", pPubKey);



    let d;
   
    if(hasEvenY(P)) 
        d = d0;
    else
        d = order - d0;
    
    console.log("is it even?", hasEvenY(P));
    console.log("> d: ", d);
    console.log("> d0:", d0);

    //k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n

    const nonceValueInt = parseInt(crypto.randomBytes(32).toString('hex'), 16);
    const hashMsg = crypto.createHash('sha256').update("HOPE2SEEUAGAIN").digest('hex');
    const combinedHash = crypto.createHash('sha256').update(hashMsg + nonceValueInt.toString() ).digest('hex');
    
    const k0 = BigInt(parseInt(combinedHash, 16)) % order ;

    console.log("> k0: " + k0);

     
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
        
        const prvKeyHex = ArrayBytesToHex(prvKey);

        const prvKeyInt = BigInt(int_from_hex(prvKeyHex)) % order;

        const pubKey = babyJub.mulPointEscalar(babyJub.Base8, prvKeyInt);


        let prvKeyJson;

        if(hasEvenY(pubKey)) 
            prvKeyJson = prvKeyInt;
        else
            prvKeyJson = order - prvKeyInt;

        const pPubKey =  babyJub.packPoint(pubKey);
        console.log("key pub: ", pPubKey);
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
