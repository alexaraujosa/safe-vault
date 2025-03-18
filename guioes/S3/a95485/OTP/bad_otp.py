#!/usr/bin/env python3

import sys
import random


def bad_prng(n):
    """ an INSECURE pseudo-random number generator """
    random.seed(random.randbytes(2))
    return random.randbytes(n)


def setup(key_size: int, key_file: str):
    with open(key_file, "wb") as f:
        f.write(bad_prng(key_size))


def encrypt(plaintext_file: str, key_file: str):
    with open(plaintext_file, "rb") as f:
        plaintext = f.read()

    with open(key_file, "rb") as f:
        key = f.read()

    if len(plaintext) > len(key):
        print("Security Warning: The key is smaller than the plaintext")

    ciphertext = bytes([a ^ b for a, b in zip(plaintext, key)])

    with open(plaintext_file + ".enc", "wb") as f:
        f.write(ciphertext)


def decrypt(ciphertext_file: str, key_file: str):
    with open(ciphertext_file, "rb") as f:
        ciphertext = f.read()

    with open(key_file, "rb") as f:
        key = f.read()

    plaintext = bytes([a ^ b for a, b in zip(ciphertext, key)])

    with open(ciphertext_file + ".dec", "wb") as f:
        f.write(plaintext)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <command> [args]")
        print("Examples:")
        print(f"    {sys.argv[0]} setup <key_size> <key_file>")
        print(f"    {sys.argv[0]} enc <plaintext_file> <key_file>")
        print(f"    {sys.argv[0]} dec <ciphertext_file> <key_file>")
        sys.exit(1)

    command = sys.argv[1]

    match command:
        case "setup":
            setup(int(sys.argv[2]), sys.argv[3])
        case "enc":
            encrypt(sys.argv[2], sys.argv[3])
        case "dec":
            decrypt(sys.argv[2], sys.argv[3])
        case _:
            print(f"Invalid command: {command}")
            sys.exit(1)


if __name__ == '__main__':
    main()
