#!/usr/bin/env python3

import sys
import struct
import os
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.backends import default_backend

KEY_SIZE   = 32
NONCE_SIZE =  8
IV_SIZE    = 16  # AES block size


def generate_key(key_file: str) -> None:
    """Generate and store a truly random encryption key."""
    with open(key_file, "wb") as f:
        f.write(os.urandom(KEY_SIZE))


def encrypt(file_path: str, key_file: str, method: str = None) -> None:
    """Encrypt a file using ChaCha20 or AES and store the result with a .enc extension."""
    with open(key_file, "rb") as f:
        key = f.read()

    nonce = os.urandom(NONCE_SIZE)
    counter = 0
    full_nonce = struct.pack("<Q", counter) + nonce

    if method == "aes-ctr":
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.CTR(full_nonce), backend=default_backend())
    elif method == "aes-cbc":
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.CBC(full_nonce), backend=default_backend())
    elif method == "chacha20":
        algorithm = algorithms.ChaCha20(key, full_nonce)
        cipher = Cipher(algorithm, mode=None)  # ChaCha20 does not require a mode
    else:
        raise ValueError(f"Unsupported method: {method}")

    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Apply padding for AES CBC mode if needed
    if method == "aes-cbc":
        padding_length = IV_SIZE - (len(plaintext) % IV_SIZE)
        plaintext += bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(plaintext)

    with open(file_path + ".enc", "wb") as f:
        f.write(nonce + ciphertext)


def decrypt(file_path: str, key_file: str, method: str = None) -> None:
    """Decrypt a previously encrypted file and store the result with a .dec extension."""
    with open(key_file, "rb") as f:
        key = f.read()

    with open(file_path, "rb") as f:
        file_data = f.read()

    nonce = file_data[:NONCE_SIZE]
    counter = 0
    full_nonce = struct.pack("<Q", counter) + nonce

    if method == "aes-ctr":
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.CTR(full_nonce), backend=default_backend())
    elif method == "aes-cbc":
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.CBC(full_nonce), backend=default_backend())
    elif method == "chacha20":
        algorithm = algorithms.ChaCha20(key, full_nonce)
        cipher = Cipher(algorithm, mode=None)  # ChaCha20 does not require a mode
    else:
        raise ValueError(f"Unsupported method: {method}")

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(file_data[NONCE_SIZE:])

    # Remove padding for AES CBC mode if needed
    if method == "aes-cbc":
        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]

    with open(file_path + ".dec", "wb") as f:
        f.write(plaintext)


def process_args(method: str = None):
    if len(sys.argv) < 3:
        print("Usage:\n"
              f"  python3 {sys.argv[0]} setup <key_file>\n"
              f"  python3 {sys.argv[0]} <enc|dec> <file_path> <key_file>")
        sys.exit(1)

    match sys.argv[1]:
        case "setup":
            generate_key(sys.argv[2])
        case "enc":
            encrypt(sys.argv[2], sys.argv[3], method=method)
        case "dec":
            decrypt(sys.argv[2], sys.argv[3], method=method)
        case _:
            print("Invalid option")
            sys.exit(1)
