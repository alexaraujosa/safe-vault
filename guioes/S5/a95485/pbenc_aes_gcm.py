import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_LEN = 12
NONCE_BYTELEN = 1
_NONCE_LEN = NONCE_LEN.to_bytes(NONCE_BYTELEN, "little")


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
    aad = b"authenticated but unencrypted data"

    with open(msgFile, "rb") as mf:
        msg = mf.read()

        nonce = os.urandom(NONCE_LEN)
        key = derivate(nonce, passwd)

        aesgcm = AESGCM(key)
        enc = aesgcm.encrypt(nonce, msg, aad)

        with open(outFile, "wb") as of:
            of.write(_NONCE_LEN)
            of.write(nonce)
            of.write(enc)


def dec(encFile, passwd):
    outFile = f"{'.'.join(encFile.split('.')[0:-1])}.dec"
    aad = b"authenticated but unencrypted data"

    with open(encFile, "rb") as ef:
        efNonceLen = int.from_bytes(ef.read(NONCE_BYTELEN), "little")
        efNonce = ef.read(efNonceLen)
        efEnc = ef.read()

        key = derivate(efNonce, passwd)

        aesgcm = AESGCM(key)
        dec = aesgcm.decrypt(efNonce, efEnc, aad)

        with open(outFile, "wb") as of:
            of.write(dec)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        exit(1)
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
