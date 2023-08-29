const chai = require("chai");
const path = require("path");

const wasm_tester = require("circom_tester").wasm;

const buildBabyjub = require("circomlibjs").buildBabyjub;

const Scalar = require("ffjavascript").Scalar;

const assert = chai.assert;

function print(circuit, w, s) {
    console.log(s + ": " + w[circuit.getSignalIdx(s)]);
}

function buffer2bits(buff) {
    const res = [];
    for (let i=0; i<buff.length; i++) {
        for (let j=0; j<8; j++) {
            if ((buff[i]>>j)&1) {
                res.push(1n);
            } else {
                res.push(0n);
            }
        }
    }
    return res;
}


describe("Schnorr test", function () {
    let circuit;
    let eddsa;
    let babyJub;
    let F;

    this.timeout(100000);

    before( async () => {
        babyJub = await buildBabyjub();
        F = babyJub.F;
        circuit = await wasm_tester(path.join(__dirname, "circuits", "schnorr_test.circom"));
    });


    it("Sign a single 10 bytes from 0 to 9", async () => {
        const msg = Buffer.from("00010203040506070809", "hex");

//      const prvKey = crypto.randomBytes(32);


       // const signature = eddsa.signPedersen(prvKey, msg);

        const w = await circuit.calculateWitness({ /* still to decide*/ }, true);

        await circuit.checkConstraints(w);
    });
});