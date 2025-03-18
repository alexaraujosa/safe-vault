#!/usr/bin/env python3

import sys
from collections import Counter
from itertools   import product
from vigenere    import vigenere
from portuguese  import letter_frequency_iterator

ALPHABET = [chr(i) for i in range(65, 91)]


def get_most_frequent_letters(ciphertext: str) -> list[str]:
    counts = Counter(char for char in ciphertext if char in ALPHABET)
    return [char for char, _ in counts.most_common()]


def attack(ciphertext: str, key_length: int, words: list[str]) -> tuple[str, str]:
    freq_letters = list(letter_frequency_iterator())
    most_frequent_letters = [
        get_most_frequent_letters(ciphertext[i::key_length])
        for i in range(key_length)
    ]

    # Generate all combinations of keys based on the most frequent letters
    for key_guess in product(*(freq_letters for _ in range(key_length))):
        key = ''.join(
            ALPHABET[(ALPHABET.index(most_frequent_letters[i][0]) - ALPHABET.index(letter)) % 26]
            for i, letter in enumerate(key_guess)
        )

        plaintext = vigenere(ciphertext, key, enc=False)
        if any(word in plaintext for word in words):
            return key, plaintext

    return None, None


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 vigenere_attack.py <key_length> <ciphertext> <known_words...>")
        sys.exit(1)

    key_length = int(sys.argv[1])
    ciphertext = sys.argv[2]
    words      = sys.argv[3:]

    key, plaintext = attack(ciphertext, key_length, words)

    if key and plaintext:
        print(key)
        print(plaintext)
        sys.exit(0)

    sys.exit(1)


if __name__ == "__main__":
    main()
