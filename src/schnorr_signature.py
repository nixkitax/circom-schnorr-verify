import os 
import json
import sys
import generate_key_pairs as gen_keys
import ecdsa
import argparse

DEFAULT_NUM_PUBLIC_KEYS = 3

def schnorr_sign(private_key, message):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    signature = sk.sign(message.encode(), hashfunc=ecdsa.util.sha256)

    return signature

def zero_arg_schorr(numKeys):
    personal_keys = gen_keys.generate_key_pairs(1)
    private_key_hex = personal_keys[0]["private_key"] 
    public_key_hex = personal_keys[0]["public_key"]
    print(public_key_hex, ":", private_key_hex)
    private_key = bytes.fromhex(private_key_hex)
    
    message = "Hello, world!"

    signature = schnorr_sign(private_key, message)
    other_keys = gen_keys.generate_key_pairs(numKeys) 

    pub_keys = [pub_key["public_key"] for pub_key in other_keys]

    result = {
        "signature": signature.hex(),
        "public_keys": pub_keys
    }
        
    create_json(result)

def only_mex_arg_schnorr(mex, numKeys):
    if mex is None:
        print("Errore: Deve essere fornito un messaggio per la firma 'only_mex'.")
        return
    personal_keys = gen_keys.generate_key_pairs(1)
    private_key_hex = personal_keys[0]["private_key"] 
    private_key = bytes.fromhex(private_key_hex)
    
    message = mex

    signature = schnorr_sign(private_key, message)
    other_keys = gen_keys.generate_key_pairs(numKeys) 

    pub_keys = [pub_key["public_key"] for pub_key in other_keys]

    result = {
        "signature": signature.hex(),
        "public_keys": pub_keys
    }
        
    create_json(result)
    
def verify_signature():
    input_path = os.path.abspath("../inputs/schnorrSign/input.json")
    with open(input_path) as json_file:
        data = json.load(json_file)
    
    signature_hex = data["signature"]
    public_keys = data["public_keys"]
    
    signature = bytes.fromhex(signature_hex)
    for public_key_hex in public_keys:
        public_key = bytes.fromhex(public_key_hex)
        vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
        try:
            vk.verify(signature, b'', sigdecode=ecdsa.util.sigdecode_string)
            print("Public key verified the signature.")
            return True  # Signature is valid for this public key
        except ecdsa.BadSignatureError:
            pass
    print("No valid public key found for the given signature.")
    return False  # No valid public key found for the given signature
# ----------------------------------------------------------------------------

def exec(args):
    if args.type == "zero":
        zero_arg_schorr(args.num_keys)
    elif args.type == "only_mex":
        only_mex_arg_schnorr(args.message, args.num_keys)
    elif args.verify : 
        verify_signature()
        
    
def create_json(result):
    output_file_path = os.path.join("../inputs/schnorrSign", "input.json")
    with open(output_file_path, "w") as output_file:
        json.dump(result, output_file, indent=4)        
    print("created json at ", output_file_path)
    
def main():
    parser = argparse.ArgumentParser(description="Generatore di firme Schnorr")
    parser.add_argument("-t", "--type", choices=["zero", "only_mex", "mex_plus_publickey", "verify"], help="Tipo di input (es. zero)")
    parser.add_argument("-m", "--message", help="Il messaggio da firmare")
    parser.add_argument("-n", "--num_keys", type=int, default=DEFAULT_NUM_PUBLIC_KEYS, help="Numero di chiavi pubbliche da creare")
    parser.add_argument("-v", "--verify", action="store_true", help = "To use to verify if at least one public key is actually the one that signed the mex, NOT SECURE/JUST FOR DEBUG")
    
    args = parser.parse_args()
    
    num_public_keys = args.num_keys
    
    exec(args)  

if __name__ == "__main__":
    main()
