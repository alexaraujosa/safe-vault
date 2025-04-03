import os
import sys
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


NONCE_LEN = 16
NONCE_BYTELEN = 1
_NONCE_LEN = NONCE_LEN.to_bytes(NONCE_BYTELEN, "little")

def enc(msgFile, passwd):
    outFile = f"{msgFile}.enc"

    with open(msgFile, "rb") as mf:
        msg = mf.read()

        nonce = os.urandom(NONCE_LEN)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=nonce,
            iterations=480000,
        )
        key = kdf.derive(bytes(passwd, "ascii"))
        
        cc = ChaCha20(key, nonce)
        cce = Cipher(cc, mode=None).encryptor()

        enc = cce.update(msg)

        with open(outFile, "wb") as of:
            of.write(_NONCE_LEN)
            of.write(nonce)
            of.write(enc)

def dec(encFile, passwd):
    outFile = f"{'.'.join(encFile.split('.')[0:-1])}.dec"

    with open(encFile, "rb") as ef:
        efNonceLen = int.from_bytes(ef.read(NONCE_BYTELEN), "little")
        efNonce = ef.read(efNonceLen)
        efEnc = ef.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=efNonce,
            iterations=480000,
        )
        key = kdf.derive(bytes(passwd, "ascii"))

        cc = ChaCha20(key, efNonce)
        ccd = Cipher(cc, mode=None).decryptor()

        dec = ccd.update(efEnc)

        with open(outFile, "wb") as of:
            of.write(dec)
            

if __name__ == "__main__":
    if len(sys.argv) < 2: exit(1)
    op = sys.argv[1]

    match op:
        case "enc":
            msgFile = sys.argv[2]
            passwd = input("Passphrase: ")
            enc(msgFile, passwd)
        case "dec":
            encFile = sys.argv[2]
            passwd = input("Passphrase: ")
            dec(encFile, passwd)