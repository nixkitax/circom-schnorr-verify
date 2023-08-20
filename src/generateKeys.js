const fs = require('fs')
const crypto = require("crypto");
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

const ArrayBytesToHex= (bytes)  => {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

function xorBytes(arr1, arr2, arr3) {
    const result = [];

    const length = Math.min(arr1.length, arr2.length, arr3.length);

    for (let i = 0; i < length; i++) {
    result.push(arr1[i] ^ arr2[i] ^ arr3[i]);
    }

    return result;
}


(async () => {
    try {
        eddsa = await buildEddsa();
        babyJub = await buildBabyjub();
        
        F = babyJub.F;

        const msg = Buffer.from("00010203040506070809", "hex");
        
        const prvKey = crypto.randomBytes(32);

        const prvKeyInt = BigInt(`0x${prvKey.toString("hex")}`);

        console.log(prvKeyInt);

        const prvKeyHex = prvKeyInt.toString(16);

        const pubKey = babyJub.mulPointEscalar(babyJub.Base8, prvKeyInt);



        const pPubKey = babyJub.packPoint(pubKey);


        const pubKeyHex = ArrayBytesToHex(pPubKey);


        
        console.log("> private key [hex]: ", prvKeyHex);
        console.log("> public  key [hex]: ", pubKeyHex)

        let pair = {
            "privateKey": prvKeyHex,
            "publicKey": pubKeyHex
        };

        let object = {
            "$schema": "./users_schema.json",
            "users": [
                {
                "privateKey": prvKeyHex,
                "publicKey": pubKeyHex
                }
            ]
        };

        object.users.push(pair);

        console.log(object);


        //signature
        // Genera un nonce casuale nell'intervallo [0, ordine della curva - 1]
        
        const nonceValue = crypto.randomBytes(32);

        const nonceValueInt = BigInt(`0x${nonceValue.toString("hex")}`);

        const hashMsg = crypto.createHash('sha256').update("HOPE2SEEUAGAIN").digest('hex');

        console.log(nonceValueInt);
        console.log(prvKeyInt)
        console.log(hashMsg);

        var t = xorBytes(prvKeyInt, hashMsg , nonceValueInt);

        console.log(t);

       // const nonceValueInt = BigInt(`0x${nonceValue.toString("hex")}`);
    
            
       
        /*
            d = d0 if has_even_y(P) else n - d0
        t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", get_aux_rand()))
        k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n
        if k0 == 0:
            raise RuntimeError('Failure. This happens only with negligible probability.')
        R = point_mul(G, k0)
        ----
        const t = xorBytes(bytesFromInt(d), taggedHash("BIP0340/aux", getAuxRand()));
        const k0Bytes = taggedHash("BIP0340/nonce", concatenateArrays(t, bytesFromPoint(P), msg));
        const k0BigInt = intFromBytes(k0Bytes) % n;

        if (k0BigInt === 0n) {
            throw new Error("Failure. This happens only with negligible probability.");
        }

        const R = pointMul(G, k0BigInt);

        */


        /*
        const prvKey = crypto.randomBytes(32);

        const prvKeyInt = BigInt(`0x${prvKey.toString("hex")}`);
        const prvKeyHex = prvKeyInt.toString(16);

        const pubKey = babyJub.mulPointEscalar(babyJub.Base8, prvKeyInt);

        const pPubKey = babyJub.packPoint(pubKey);


        const pubKeyHex = ArrayBytesToHex(pPubKey);

        */
    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();
