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

const bytesToHex= (bytes)  => {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

(async () => {
    try {
        eddsa = await buildEddsa();
        babyJub = await buildBabyjub();
        F = babyJub.F;

        const msg = Buffer.from("00010203040506070809", "hex");
        const prvKey = crypto.randomBytes(32);

        const prvKeyInt = BigInt(`0x${prvKey.toString("hex")}`);

        const pubKey = babyJub.mulPointEscalar(babyJub.Base8, prvKeyInt);

        const pPubKey = babyJub.packPoint(pubKey);

        const prvKeyHex = prvKeyInt.toString(16);
        const pubKeyHex = bytesToHex(pPubKey);

        console.log("> private key [hex]: ", prvKeyHex);
        console.log("> public  key [hex]: ", pubKeyHex)

    } catch (error) {
        console.error("Si è verificato un errore:", error);
    }
})();
