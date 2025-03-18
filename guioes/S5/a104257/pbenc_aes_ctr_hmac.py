import os
import sys
import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


NONCE_LEN = 16
NONCE_BYTELEN = 1
_NONCE_LEN = NONCE_LEN.to_bytes(NONCE_BYTELEN, "little")
HNONCE_BYTELEN = 1

def derivate(nonce, passwd):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        iterations=480000,
    )
    return kdf.derive(bytes(passwd, "ascii"))

def enc(msgFile, passwd):
    outFile = f"{msgFile}.enc"

    with open(msgFile, "rb") as mf:
        msg = mf.read()

        nonce = os.urandom(NONCE_LEN)
        key = derivate(nonce, passwd)
        
        cc = algorithms.AES(key)
        cce = Cipher(cc, mode=modes.CTR(nonce)).encryptor()

        enc = cce.update(msg)

        hnonce = os.urandom(NONCE_LEN)
        hkey = derivate(hnonce, passwd)
        h = hmac.HMAC(hkey, hashes.SHA256())
        h.update(enc)
        henc = h.finalize()

        with open(outFile, "wb") as of:
            of.write(_NONCE_LEN)
            of.write(nonce)
            of.write(hnonce)
            of.write(len(henc).to_bytes(1, "little"))
            of.write(henc)
            of.write(enc)

def dec(encFile, passwd):
    outFile = f"{'.'.join(encFile.split('.')[0:-1])}.dec"

    with open(encFile, "rb") as ef:
        efNonceLen = int.from_bytes(ef.read(NONCE_BYTELEN), "little")
        efNonce = ef.read(efNonceLen)
        efHNonce = ef.read(efNonceLen)
        efHEncLen = int.from_bytes(ef.read(HNONCE_BYTELEN), "little")
        efHEnc = ef.read(efHEncLen)
        efEnc = ef.read()

        hkey = derivate(efHNonce, passwd)
        h = hmac.HMAC(hkey, hashes.SHA256())
        h.update(efEnc)
        h.verify(efHEnc)

        key = derivate(efNonce, passwd)

        cc = algorithms.AES(key)
        ccd = Cipher(cc, mode=modes.CTR(efNonce)).decryptor()

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