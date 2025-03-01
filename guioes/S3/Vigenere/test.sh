#!/bin/bash

decoded=(
    "AMOREFOGOQUEARDESEMSEVER"
    "AVERDADEIRAAFEICAONALONGAAUSENCIASEPROVA"
    "MUDAMSEOSTEMPOSMUDAMSEASVONTADES"
)

keys=(
    "XM"
    "ASDW"
    "VON"
)

known_words=(
    "TESTE AMOR"
    "TESTE AFEICAO"
    "TESTE VONTADES"
)

encoded=()

echo -e "\nTesting Vigenere encryption\n"

for i in "${!decoded[@]}"; do
    echo "Encrypting: ${decoded[$i]}"
    # print('Usage: python vigenere.py <enc|dec> <key> <msg>')
    encoded[i]=$(./vigenere.py enc "${keys[$i]}" "${decoded[$i]}")
    echo "Encrypted:  ${encoded[$i]}"
    echo
done

echo -e "\nTesting Vigenere attack\n"

for i in "${!encoded[@]}"; do
    echo "Attacking: ${encoded[$i]}"
    key_length=${#keys[$i]}
    # print("Usage: python3 vigenere_attack.py <key_length> <ciphertext> <words...>")
    ./vigenere_attack.py "$key_length" "${encoded[$i]}" ${known_words[$i]}
    echo
done

exit 0
