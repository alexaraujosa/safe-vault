#!/usr/bin/env python3

import sys


def main():
    if len(sys.argv) < 3:
        print('Usage: python caesar_attack.py <text> <known_words...>')
        sys.exit(1)

    text = sys.argv[1].upper()
    known_words = list(map(str.upper, sys.argv[2:]))

    for shift in range(26):
        r = ""
        for c in text:
            if not c.isalpha():
                r += c
                continue

            r += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))

        for word in known_words:
            if word in r:
                print(chr(shift + ord('A')))
                print(r)
                sys.exit(0)

    sys.exit(1)


main()
