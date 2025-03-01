#!/usr/bin/env python3

import sys


def main():
    if len(sys.argv) != 4:
        print('Usage: python cesar.py <enc|dec> <key> <msg>')
        sys.exit(1)

    method  = sys.argv[1]
    key     = sys.argv[2].upper()
    message = sys.argv[3].upper()

    if method != "enc" and method != "dec":
        print("Method must be 'enc' or 'dec'.")
        sys.exit(1)

    if len(key) != 1 or not key.isalpha():
        print("Key must be a single letter.")
        sys.exit(1)

    shift = ord(key) - ord('A')
    if method == "dec":
        shift = -shift

    r = ""
    for c in message:
        if not c.isalpha():
            r += c
            continue

        r += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))

    print(r)


main()
