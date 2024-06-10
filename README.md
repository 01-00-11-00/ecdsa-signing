# ECDSA Signing Class

This Python project includes an `EcdsaSigning` class that implements the Elliptic Curve Digital Signature Algorithm (ECDSA). ECDSA is a cryptographic algorithm used for digital signatures and is based on elliptic curve cryptography, which provides high security with relatively short key lengths.

## Getting Started

### Dependencies

- Python 3.x
- cryptography
- hashlib

### Installing

Clone the repository using the following command:

```bash
git clone https://github.com/01-00-11-00/ecdsa-signing.git
```

Install the required packages using the following command:

````bash
pip install cryptography hashlib
````

## Features

The `EcdsaSigning` class includes the following methods:

- `read_keys(file_path: str)`: Reads a private key from a PEM file.
- `read_signature(file_path: str) -> tuple`: Reads a signature from a binary file.
- `read_message(file_path: str) -> bytes`: Reads a message from a binary file.
- `create_public_key_pem(public_key: tuple)`: Creates a PEM file from a public key.
- `create_public_key(private_key: int) -> tuple`: Creates a public key from a private key.
- `create_signed_bin(message: bytes, private_key: int, k: int, file_path="output/signature.bin")`: Creates a signed binary file from a message, a private key, and a nonce.
- `create_message_bin(message: bytes, file_path="output/message.bin")`: Creates a binary file from a message.
- `ecdsa_sign(message, private_key, k) -> tuple`: Signs a message using ECDSA.
- `ecdsa_verify(public_key, message, signature)`: Verifies a signature using ECDSA.
- `asn1_encode(signature: tuple) -> bytes`: Encodes a signature using ASN.1.
- `asn1_decode(encoded_sequence: bytes) -> tuple`: Decodes a signature using ASN.1.
- `check_for_identical_nonce(message_1: bytes, message_2: bytes, sig_1: tuple, sig_2: tuple) -> int or None`: Checks if two messages were signed using the same nonce.

## Usage

To use the `EcdsaSigning` class, import it into your Python script and create an instance of the class. You can then call the methods on the instance as needed.

```python
from utils.ecdsa_signing import EcdsaSigning

signing = EcdsaSigning()
```

## Authors

01-00-11-00

ex. [@01-00-11-00](https://github.com/01-00-11-00)

## Version History

- 0.1
    - Initial Release