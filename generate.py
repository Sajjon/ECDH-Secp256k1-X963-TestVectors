from __future__ import absolute_import
import os
import json
import binascii
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf import x963kdf, hkdf
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from ecdsa import SigningKey, SECP256k1

from secp256k1 import PrivateKey as ffiPrivateKey

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
    ecdsa_private_key = SigningKey.from_string(
        private_key_bytes, curve=SECP256k1)
    ecdsa_public_key = ecdsa_private_key.verifying_key

    assert ecdsa_private_key.to_string().hex() == private_key_hex
    assert ecdsa_public_key.to_string().hex() == public_key_hex[-128:]

    ffi_privkey = ffiPrivateKey(private_key_bytes)
    ffi_privkey._update_public_key()

    assert ffi_privkey.serialize() == private_key_hex
    assert ffi_privkey.pubkey.serialize(False).hex() == public_key_hex

    return (ffi_privkey, private_key, public_key, private_key_hex, public_key_hex)


def generate_vector():
    (alice_ffi_priv, alice_private_key, alice_public_key, alice_private_key_hex,
     alice_public_key_hex) = generate_keypair()
    alice_ffi_pub = alice_ffi_priv.pubkey
    (bob_ffi_priv, bob_private_key, bob_public_key, bob_private_key_hex,
     bob_public_key_hex) = generate_keypair()
    bob_ffi_pub = bob_ffi_priv.pubkey

    alice_ffi_priv_bytes = binascii.unhexlify(alice_ffi_priv.serialize())
    bob_ffi_priv_bytes = binascii.unhexlify(bob_ffi_priv.serialize())

    assert len(alice_ffi_priv_bytes) == 32
    assert len(bob_ffi_priv_bytes) == 32

    ecdh_btc = "Bitcoin"
    ecdh_variants = ["ASN1X963", ecdh_btc]
    infos = ["", "such info", "I don't respect therapy because I'm a scientist. Because I invent, transform, create, and destroy for a living, when I don't like something about the world, I change it."]

    outcomes = []

    for ecdh_variant in ecdh_variants:

        ecdh_shared_key_ab = bob_ffi_pub.ecdh(alice_ffi_priv_bytes) if ecdh_variant == ecdh_btc else alice_private_key.exchange(
            ec.ECDH(), bob_public_key)

        ecdh_shared_key_ba = alice_ffi_pub.ecdh(bob_ffi_priv_bytes) if ecdh_variant == ecdh_btc else bob_private_key.exchange(
            ec.ECDH(), alice_public_key)

        assert ecdh_shared_key_ab == ecdh_shared_key_ba
        ecdh_shared_key = ecdh_shared_key_ab

        derivedKeys = []

        for info in infos:

            xkdf = x963kdf.X963KDF(
                algorithm=hashes.SHA256(),
                length=32,
                sharedinfo=info.encode(),
                backend=backend
            )
            x963_kdf_key = xkdf.derive(ecdh_shared_key)

            salt = os.urandom(16)
            hkdfFN = hkdf.HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=info.encode(),
            )

            hkdf_key = hkdfFN.derive(ecdh_shared_key)

            derivedKey = {
                "info": info,
                "salt": salt.hex(),
                "x963": x963_kdf_key.hex(),
                "hkdf": hkdf_key.hex()
            }
            derivedKeys.append(derivedKey)

        outcome = {
            "ecdhVariant": ecdh_variant,
            "ecdhSharedKey": ecdh_shared_key.hex(),
            "derivedKeys": derivedKeys
        }

        outcomes.append(outcome)

    return {
        "alicePrivateKey": alice_private_key_hex,
        "alicePublicKeyUncompressed": alice_public_key_hex,
        "bobPrivateKey": bob_private_key_hex,
        "bobPublicKeyUncompressed": bob_public_key_hex,
        "outcomes": outcomes
    }


def main():
    vectors = []
    for _ in range(100):
        vector = generate_vector()
        vectors.append(vector)

    number_of_tests = len(vectors)

    suite = {
        "origin": "https://github.com/Sajjon/ECDH-Secp256k1-X963-TestVectors",
        "author": "Alexander Cyon",
        "description": "Generated using lib 'pyca/cryptography', which has been cross references using two other libraries: lib 'secp256k1' (wrapper around `libsecp256k1`) and lib 'ECDSA'",
        "numberOfTests": number_of_tests,
        "algorithm": "ECDH between SECP256k1 keys using both ASN1 x9.63 ECDH and Bitcoin ECDH variant, then derived using HKDF and using x963 KDF.",
        "generatedOn": datetime.now().strftime("%Y-%m-%d"),
        "vectors": vectors,
    }
    print(json.dumps(suite, indent=4))


if __name__ == "__main__":
    main()
