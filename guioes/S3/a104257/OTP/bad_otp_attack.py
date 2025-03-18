#!/usr/bin/env python3

import sys
import random

SEED_SIZE = 2  # Bytes


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <ciphertext_file> <known_words...>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        ciphertext = f.read()

    known_words = sys.argv[2:]

    num_seeds = 2 ** (8 * SEED_SIZE)
    # print(f"Testing all {num_seeds} possible seeds...")

    for seed in range(num_seeds):
        # Generate seed (big-endian)
        random.seed(seed.to_bytes(SEED_SIZE, "big"))

        # Recreate the key using bad PRNG
        # NOTE: This value must be the same used in the key!
        # If the text is 18 bytes long, and the key used was 30 bytes long
        # We can't recreate the key, and therefore can't decrypt the text
        key = random.randbytes(len(ciphertext))

        # Decrypt ciphertext
        plaintext = bytes([a ^ b for a, b in zip(ciphertext, key)])

        # Check for any known words in plaintext
        if any(word.encode() in plaintext for word in known_words):
            # print(f"Seed: {seed.to_bytes(SEED_SIZE, 'big')}")
            # print(f"Key: {key}")
            # print(f"Plaintext: {plaintext.decode(errors='ignore')}")
            print(plaintext.decode(errors="ignore"), end="")
            sys.exit(0)

    # print("No valid key found.")
    sys.exit(1)


if __name__ == "__main__":
    main()
