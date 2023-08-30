export const has_even_y = (P) => y(P) % 2n == 0n;

export const array_bytes_to_hex = (bytes) => {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
};

export const hex_to_array_bytes = (hexString) => {
	const bytes = [];
	for (let i = 0; i < hexString.length; i += 2) {
		bytes.push(parseInt(hexString.substr(i, 2), 16));
	}
	return bytes;
};

export const byte_array_to_int = (byteArray) => {
	let bigIntValue = 0n;
	for (let i = 0; i < byteArray.length; i++) {
		bigIntValue += BigInt(byteArray[i]) * 256n ** BigInt(byteArray.length - 1 - i);
	}
	return bigIntValue;
};

export const big_int_from_hex = (str) => BigInt('0x' + str);

export const hex_from_big_int = (bigIntValue) => {
	if (typeof bigIntValue !== 'bigint') {
		throw new Error('Input deve essere un valore BigInt');
	}

	if (bigIntValue < 0) {
		throw new Error('Il valore BigInt non può essere negativo');
	}

	return bigIntValue.toString(16);
};

export const int_to_byte_array = (intValue) => {
	const byteArray = [];

	if (intValue === 0) {
		byteArray.push(0);
		return byteArray;
	}

	const isNegative = intValue < 0;
	if (isNegative) {
		intValue = -intValue;
	}

	while (intValue > 0) {
		byteArray.unshift(Number(intValue & 0xffn));
		intValue >>= 8n;
	}

	if (isNegative) {
		byteArray.unshift(0x80); // Aggiunge un byte per segnalare il numero negativo
	}

	return byteArray;
};

export const hex_to_big_int = (hexValue) => {
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
};

export const x = (P) => byte_array_to_int(P[0]);

export const y = (P) => byte_array_to_int(P[1]);
