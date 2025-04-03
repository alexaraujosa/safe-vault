import os
import sys
import struct
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xor(a, b): return bytes(abyte ^ bbyte for abyte, bbyte in zip(a, b))

def attack(fctxt, pos, ptxtAtPos, newPtxtAtPos):
    outFile = f"{'.'.join(fctxt.split('.')[0:-1])}.attck"

    with open(fctxt, "rb") as f:
        f.seek(pos)
        sec = f.read(len(ptxtAtPos))

        cipher = xor(sec, bytes(ptxtAtPos, "ascii"))
        ncipher = xor(cipher, bytes(newPtxtAtPos, "ascii"))

        with open(outFile, "wb") as of:
            f.seek(0)
            buf = f.read()
            of.write(buf)
            
            of.seek(pos)
            of.write(ncipher)

if __name__ == "__main__":
    if len(sys.argv) < 4: exit(1)

    fctxt        = sys.argv[1]
    pos          = int(sys.argv[2])
    ptxtAtPos    = sys.argv[3]
    newPtxtAtPos = sys.argv[4]
    attack(fctxt, pos, ptxtAtPos, newPtxtAtPos)
    