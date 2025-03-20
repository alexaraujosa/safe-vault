#!/usr/bin/env python3

# ciphertext = plaintext ⊕ keystream
# keystream  = plaintext ⊕ ciphertext

import sys


def modify_ciphertext(ciphertext_file, position, original_char, new_char):
    """Modify the ciphertext at a specific position to change a known plaintext byte."""
    with open(ciphertext_file, "rb") as f:
        ciphertext = bytearray(f.read())  # bytearray allows item assignment

    if position < 0 or position >= len(ciphertext):
        print("Error: Position out of bounds.")
        sys.exit(1)

    # Modify ciphertext: C' = C ⊕ P ⊕ P'
    ciphertext[position] ^= ord(original_char) ^ ord(new_char)

    with open(ciphertext_file + ".attck", "wb") as f:
        f.write(ciphertext)


def main():
    if len(sys.argv) != 5:
        print("Usage: python3 chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
        sys.exit(1)

    ciphertext_file = sys.argv[1]
    position = int(sys.argv[2])
    original_char = sys.argv[3]
    new_char = sys.argv[4]

    if len(original_char) != 1 or len(new_char) != 1:
        print("Error: <ptxtAtPos> and <newPtxtAtPos> must be single characters.")
        sys.exit(1)

    modify_ciphertext(ciphertext_file, position, original_char, new_char)


if __name__ == "__main__":
    main()
