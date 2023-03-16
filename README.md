# ECDH secp256k1 X9.63 Test vectors

## Generate

```sh
pip install -r requirements.txt && python generate.py
```

## Test vector format
```json
[
    {
        "alicePrivateKey": "fb2cf01d9a68f33a3d307f2b449d27fc1d11a334aaf75612acfbf193b6376ffd",
        "alicePublicKeyUncompressed": "04555d38e0757ad884e76b3bb30276e17ae627b492af88939e954665e889f7b212497f86a228f9f9d21bdd01233ab4844bdb9ae1cd0e497a6e1a821db7e3522b5b",
        "bobPrivateKey": "89cf2ca7e20eceea2a2b8093c239bddea047b2b8d1ea9932f68e5efc880765a9",
        "bobPublicKeyUncompressed": "04f4a3443c8d9180da01bb23509a75c34dc4f01c3a8adf86d288951c553c09e43d6cdd25abbb11d3a5a35497e8889779a6abfb41576a447fb6985077611181c801",
        "ecdhSharedKey": "60d5cf8a26bfe8daa5a91cd4b1f8b28a33c60aec2586829edb075f1a3f33d1fd",
        "x963KDFOutput": "6b9181e1257400007002d8fe4e96e63d3fb087459e0ea6e742549b925dde700a"
    },
    {
        "alicePrivateKey": "0443f51e48bab6ac5fa74e82d6e0bc42d442882c6afd316f7df179a54c4b1f40",
        "alicePublicKeyUncompressed": "042637decad08405963e509963398494c30bb9390b1ad2aca68141d4dfeea3a5ba93ec8799610650196ee356ebd5834c02301193a906a4c86b81648e4c9ae4986d",
        "bobPrivateKey": "959b34247e2fce3cde7f53a4dc05b9631c6be26dd1c2b9f7383fa0dcb9baa20e",
        "bobPublicKeyUncompressed": "04412d617807ac5320cec8a0e275cb62191872ba7178facd6985788930061cddc7d0f6bbf160cb28b55add3ab40656db655e3277b1391f141ae2d07079d09be3ec",
        "ecdhSharedKey": "d830d5635a83de15dd30a8d885d9afabd8e2ba5ff8b4a059ff06182a786428f0",
        "x963KDFOutput": "7f8ac9a3c48d1577d09f5621d40cd6827c4d905487f627fef4e7d3a7db7236db"
    },
    {
        "alicePrivateKey": "d5c4019d4557182aa350c97d3f1975f66b960b7121c353214beb407c382ebad5",
        "alicePublicKeyUncompressed": "04f4f86d85ab6eadf9c4664b8d193fe6d32dceb6837be02d55c99ff5651b2d6a03ed5fe40986fe3cb3d576ed919ba46eb386ea152f79bf79a84923d4ebacde8895",
        "bobPrivateKey": "9cec89244cc8c326977512b00386de4ef1357dc25b4b380d7c5a0a01122298c1",
        "bobPublicKeyUncompressed": "0421019125437c67566e514b023de5a5a2b1768049df56e140602200808a6c83cad34e08b4759e8ffa720c0eee476ee44cbebdce57b38d27018f86b38bdc555c1d",
        "ecdhSharedKey": "74de28bbbabcae9b1bd1ccd908ad343bf5fea4cb8d84bb9be6ef88feeebfbe59",
        "x963KDFOutput": "bc3452efd55c21e16f95b42f8976bd370fce9093854b6607f19f6c84f328fc05"
    }
]
```