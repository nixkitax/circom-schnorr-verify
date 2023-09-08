function rimuoviI(input) {
  // Dividi la stringa in righe
  const righe = input.split('\n');

  // Inizializza una stringa vuota per il risultato
  let risultato = '';

  // Itera attraverso le righe
  for (const riga of righe) {
    // Rimuovi il carattere "i" seguito da uno spazio e aggiungi alla stringa risultato
    risultato += riga.replace(',', '');
  }

  // Rimuovi l'ultimo carattere di nuova riga in eccesso
  risultato = risultato.trim();

  return risultato.split('').reverse().join('');
}

function rimuoviVirgole(input) {
  // Rimuovi tutte le virgole dalla stringa
  const senzaVirgole = input.replace(/,/g, '');

  return senzaVirgole;
}

function binarioToBigInt(input) {
  // Rimuovi eventuali spazi bianchi o caratteri non validi
  const binarioPulito = input.replace(/[^01]/g, '');

  // Converte la stringa binaria in un BigInt
  const bigint = BigInt(`0b${binarioPulito}`);

  return bigint;
}

// Esempio di utilizzo:
const input = `1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1,
    0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
    1, , 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1,
    1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1,
    1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1,
    1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1,
    0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0,
    1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1,
    1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1,
    0, 1, 0`;

console.log();
console.log(binarioToBigInt(rimuoviVirgole(input)));
