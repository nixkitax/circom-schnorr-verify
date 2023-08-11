import argparse, json, sys, os
from utils import print_fails
from schnorr_lib import sha256, schnorr_sign, schnorr_musig_sign, schnorr_musig2_sign
from make_json import create_json

def main():
    parser = argparse.ArgumentParser(
        description='returns the signature and the public key from a private key and a message')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message to be signed')
    parser.add_argument('-i','--index', type=int, help="When single signing, by passing this argument the index of the keypair to use is specified otherwise the first will be used by default")
    parser.add_argument('-c', '--circom', action='store_true', help="makes input file for the (circuit -> circom -> snarkjs)")
    parser.add_argument('--musig1', action='store_true', help="aggregate signature 2 ")

    parser.add_argument('--musig2', action='store_true', help="aggregate signature 2")

    args = parser.parse_args()
    msg = args.message
    circom = args.circom # flag
    musig1 = args.musig1 # flag
    musig2 = args.musig2 # flag
    
    musig1 = False
    musig2 = False

    i = 0 # default value for single signing
    if args.index:
        i = args.index

    # Get keypair
    try:
        users = json.load(open("users.json", "r"))["users"]
    except Exception:
        print_fails("[e] Error. File nonexistent, create it with create_keypair.py")
        sys.exit(2)
    
    # Signature
    try:
        # Get message digest
        originalmess = msg
        M = sha256(msg.encode())
        X = None
        if not ( musig1 or musig2 ):
            if i < 0 or i >= len(users):
                raise RuntimeError("Index is out of range")
            print("ciao")
            sig = schnorr_sign(M, users[i]["privateKey"]) 
            print("ciao")

        elif musig1:
            sig, X = schnorr_musig_sign(M, users) 
        elif musig2:
            sig, X = schnorr_musig2_sign(M, users)
        if circom:
            try:
                users = json.load(open("users.json", "r"))["users"]
                numkeys = len(users)
                result = {
                    "message": originalmess,
                    "signature": sig.hex(),
                    "public_keys": [user["publicKey"] for user in users]
                }
            except Exception:
                print_fails("[e] Error. File nonexistent, create it with create_keypair.py")
                sys.exit(2)
        print("> Message =", originalmess)
        print("> Signature =", sig.hex())
        print("> Public key =", users[i]["publicKey"])
        print(" ")
        if circom: 
            create_json(result)
        if X is not None: 
            print("> Public aggregate=", X.hex())   
    except Exception as e:
            print_fails("[e] Exception: ", e)
            sys.exit(2)

if __name__ == "__main__":
    main()