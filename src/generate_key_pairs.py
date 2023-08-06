import ecdsa

def generate_key_pairs(num_pairs):
    key_pairs = []

    for _ in range(num_pairs):
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        key_pairs.append({
            "private_key": sk.to_string().hex(),
            "public_key": vk.to_string().hex(),
        })

    return key_pairs