import os
import sys
import struct
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IV_LEN = 16
IV_BYTELEN = 1
_IV_LEN = IV_LEN.to_bytes(IV_BYTELEN, "little")

def setup(byteLen, outFile):
    rand = os.urandom(byteLen)
    with open(outFile, "wb") as file:
        file.write(rand)

def enc(msgFile, keyFile):
    outFile = f"{msgFile}.enc"

    with open(keyFile, "rb") as kf:
        key = kf.read()
        with open(msgFile, "rb") as mf:
            msg = mf.read()
            
            iv = os.urandom(IV_LEN)
            cc = AES(key)
            cce = Cipher(cc, mode=modes.CBC(iv)).encryptor()

            enc = cce.update(msg)

            with open(outFile, "wb") as of:
                of.write(_IV_LEN)
                of.write(iv)
                of.write(enc)

def dec(encFile, keyFile):
    outFile = f"{'.'.join(encFile.split('.')[0:-1])}.dec"

    with open(keyFile, "rb") as kf:
        key = kf.read()
        with open(encFile, "rb") as ef:
            efIVLen = int.from_bytes(ef.read(IV_BYTELEN), "little")
            efIV = ef.read(efIVLen)
            efEnc = ef.read()

            cc = AES(key)
            ccd = Cipher(cc, mode=modes.CBC(efIV)).decryptor()

            dec = ccd.update(efEnc)

            with open(outFile, "wb") as of:
                of.write(dec)
            

if __name__ == "__main__":
    if len(sys.argv) < 4: exit(1)
    op = sys.argv[1]

    match op:
        case "setup":
            byteLen = int(sys.argv[2])
            outFile = sys.argv[3]
            setup(byteLen, outFile)
        case "enc":
            msgFile = sys.argv[2]
            keyFile = sys.argv[3]
            enc(msgFile, keyFile)
        case "dec":
            encFile = sys.argv[2]
            keyFile = sys.argv[3]
            dec(encFile, keyFile)