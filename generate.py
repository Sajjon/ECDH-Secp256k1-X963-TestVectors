from __future__ import absolute_import
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf import x963kdf
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from ecdsa import SigningKey, SECP256k1

backend = default_backend()

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256K1(), backend)
    public_key = private_key.public_key()
    private_key_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
    private_key_hex = private_key_bytes.hex()

    public_key_hex = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ).hex()

    # Now we cross reference compare the `cryptography (hazmat)` implementation with `ecdsa` 
    ecdsa_private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    ecdsa_public_key = ecdsa_private_key.verifying_key

    assert ecdsa_private_key.to_string().hex() == private_key_hex
    assert ecdsa_public_key.to_string().hex() == public_key_hex[-128:]

    return (private_key, public_key, private_key_hex, public_key_hex)


def generate_vector():
    (alice_private_key, alice_public_key, alice_private_key_hex, alice_public_key_hex) = generate_keypair()
    (bob_private_key, bob_public_key, bob_private_key_hex, bob_public_key_hex) = generate_keypair()

    ab_shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)
    ba_shared_key = bob_private_key.exchange(ec.ECDH(), alice_public_key)
    assert(ab_shared_key == ba_shared_key)

    xkdf = x963kdf.X963KDF(
        algorithm = hashes.SHA256(),
        length = 32,
        sharedinfo = ''.encode(),
        backend = backend
        )
    key = xkdf.derive(ab_shared_key)
    shared_key_hex = ab_shared_key.hex()
    x963_key_hex = key.hex()

    return {
        "alicePrivateKey": alice_private_key_hex,
        "alicePublicKeyUncompressed": alice_public_key_hex,
        "bobPrivateKey": bob_private_key_hex,
        "bobPublicKeyUncompressed": bob_public_key_hex,
        "ecdhSharedKey": shared_key_hex,
        "x963KDFOutput": x963_key_hex
    }

def main():
    vectors = []
    for x in range(3):
        vector = generate_vector()
        vectors.append(vector)

    suite = {
        "origin": "https://github.com/Sajjon/ECDH-Secp256k1-X963-TestVectors",
        "author": "Alexander Cyon",
        "description": "Generated using Python lib hazmat 'cryptography.hazmat'",
        "numberOfVectors": len(vectors),
        "generatedOn": datetime.now().strftime("%Y-%m-%d"),
        "vectors": vectors,
    }
    print(json.dumps(suite, indent=4))

if __name__ == "__main__":
    main()
