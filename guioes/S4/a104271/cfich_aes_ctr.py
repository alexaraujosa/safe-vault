import os
import sys
import struct
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NONCE_LEN = 16
NONCE_BYTELEN = 1
_NONCE_LEN = NONCE_LEN.to_bytes(NONCE_BYTELEN, "little")

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
            
            nonce = os.urandom(NONCE_LEN)
            cc = AES(key)
            cce = Cipher(cc, mode=modes.CTR(nonce)).encryptor()

            enc = cce.update(msg)

            with open(outFile, "wb") as of:
                of.write(_NONCE_LEN)
                of.write(nonce)
                of.write(enc)

def dec(encFile, keyFile):
    outFile = f"{'.'.join(encFile.split('.')[0:-1])}.dec"

    with open(keyFile, "rb") as kf:
        key = kf.read()
        with open(encFile, "rb") as ef:
            efNonceLen = int.from_bytes(ef.read(NONCE_BYTELEN), "little")
            efNonce = ef.read(efNonceLen)
            efEnc = ef.read()

            cc = AES(key)
            ccd = Cipher(cc, mode=modes.CTR(efNonce)).decryptor()

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