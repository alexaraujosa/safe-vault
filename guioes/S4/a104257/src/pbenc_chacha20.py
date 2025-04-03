#!/usr/bin/env python3

import sys
import struct
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.backends import default_backend

KEY_SIZE   = 32
NONCE_SIZE = 8
SALT_SIZE  = 16
PBKDF2_ITERS = 100000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from a passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode())


def encrypt(file_path: str) -> None:
    """Encrypt a file using ChaCha20 with a key derived from a passphrase."""
    passphrase = input("Enter encryption passphrase: ")
    salt = os.urandom(SALT_SIZE)
    key = derive_key(passphrase, salt)

    nonce = os.urandom(NONCE_SIZE)
    counter = 0
    full_nonce = struct.pack("<Q", counter) + nonce

    algorithm = algorithms.ChaCha20(key, full_nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext)

    with open(file_path + ".enc", "wb") as f:
        f.write(salt + nonce + ciphertext)


def decrypt(file_path: str) -> None:
    """Decrypt a previously encrypted file using ChaCha20 with a key derived from a passphrase."""
    passphrase = input("Enter decryption passphrase: ")

    with open(file_path, "rb") as f:
        file_data = f.read()

    salt = file_data[:SALT_SIZE]
    nonce = file_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = file_data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(passphrase, salt)
    counter = 0
    full_nonce = struct.pack("<Q", counter) + nonce

    algorithm = algorithms.ChaCha20(key, full_nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext)

    with open(file_path + ".dec", "wb") as f:
        f.write(plaintext)


def process_args():
    if len(sys.argv) < 3:
        print("Usage:\n"
              f"  python3 {sys.argv[0]} enc <file_path>\n"
              f"  python3 {sys.argv[0]} dec <file_path>")
        sys.exit(1)

    match sys.argv[1]:
        case "enc":
            encrypt(sys.argv[2])
        case "dec":
            decrypt(sys.argv[2])
        case _:
            print("Invalid option")
            sys.exit(1)


if __name__ == "__main__":
    process_args()
