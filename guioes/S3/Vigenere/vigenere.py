#!/usr/bin/env python3

import sys


def vigenere(msg: str, key: str, enc: bool = False) -> str:
    r = ""
    for i, c in enumerate(msg):
        if not c.isalpha():
            r += c
            continue

        shift = ord(key[i % len(key)]) - ord('A')
        if not enc:
            shift = -shift

        r += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))

    return r


def main():
    if len(sys.argv) != 4:
        print('Usage: python vigenere.py <enc|dec> <key> <msg>')
        sys.exit(1)

    enc = sys.argv[1] == "enc"
    key = sys.argv[2].upper()
    msg = sys.argv[3].upper()

    r = vigenere(msg, key, enc=enc)
    print(r)


if __name__ == '__main__':
    main()
