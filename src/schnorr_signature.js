import { buildBabyjub } from "circomlibjs";
import crypto from "crypto"
import {Scalar} from "ffjavascript"

(async () => {
    const babyJub = await buildBabyjub();

    // Genera una chiave privata casuale
    const privateKey = babyJub.F.randomScalar();

    // Calcola la chiave pubblica corrispondente
    const publicKey = babyJub.mulPointEscalar(babyJub.Generator, privateKey);

    console.log('Chiave privata:', privateKey);
    console.log('Chiave pubblica:', publicKey);
})();