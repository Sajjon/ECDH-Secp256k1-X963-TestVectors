# ECDH secp256k1 KDF Generate TestVector

This repo produces shared secrets using ECDH on the [ASN1 X9.63 standard](https://webstore.ansi.org/standards/ascx9/ansix9632011r2017) as well as ECDH using `libsecp256k1` variant (SHA-256 hash of compressed shared public point).

The test vectors are generated using [`pyca/cryptography`](https://pypi.org/project/cryptography/) and has been cross references using [`secp256k1`](https://pypi.org/project/secp256k1/) and [`ECDSA`](https://pypi.org/project/ecdsa/).

## Generate

```sh
pip install -r requirements.txt && python generate.py
```
