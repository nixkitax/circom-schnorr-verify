import os 
import json

import generate_key_pairs as gen_keys
import ecdsa

def schnorr_sign(private_key, message):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    signature = sk.sign(message.encode(), hashfunc=ecdsa.util.sha256)

    return signature

def exec():
    personal_keys = gen_keys.generate_key_pairs(1)
    private_key_hex = personal_keys[0]["private_key"] 
    private_key = bytes.fromhex(private_key_hex)
    
    message = "Hello, world!"

    signature = schnorr_sign(private_key, message)
    other_keys = gen_keys.generate_key_pairs(3) 

    pub_keys = [pub_key["public_key"] for pub_key in other_keys]


    result = {
        "signature": signature.hex(),
        "public_keys": pub_keys
    }

    output_file_path = os.path.join("../inputs/schnorrSign", "input.json")
    with open(output_file_path, "w") as output_file:
        json.dump(result, output_file, indent=4)

def main():
    exec()

if __name__ == "__main__":
    main()
