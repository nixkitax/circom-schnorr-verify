import { buildBabyjub } from "circomlibjs";
import { PublicKey, PrivateKey } from 'babyjubjub';
import crypto from "crypto"
import {Scalar} from "ffjavascript"


(async () => {
    
    //const babyJub = await buildBabyjub();

    let sk = PrivateKey.getRandObj().field;

    let privKey = new PrivateKey(sk);

    let pubKey = PublicKey.fromPrivate(privKey);

    console.log(crypto.getCurves)

    
/*

    // Genera una chiave privata casuale
    const privateKey = babyJub.F.randomScalar();

    // Calcola la chiave pubblica corrispondente
    const publicKey = babyJub.mulPointEscalar(babyJub.Generator, privateKey);

    console.log('Chiave privata:', privateKey);
    console.log('Chiave pubblica:', publicKey);*/
})();