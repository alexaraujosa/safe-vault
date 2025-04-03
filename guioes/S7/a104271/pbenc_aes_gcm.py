import io
import os
import sys
import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


NONCE_LEN = 16
NONCE_BYTELEN = 1
_NONCE_LEN = NONCE_LEN.to_bytes(NONCE_BYTELEN, "little")

MAC_KDF_LABEL = bytes("MAC and cheese", "ascii")

def deriveKDF(nonce, label, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=nonce,
        iterations=480000,
    )

    return kdf.derive(label)

def enc(msg, passwd):
    mf = io.BytesIO(msg)
    bmsg = mf.read()

    nonce = os.urandom(NONCE_LEN)
    # keySrc = deriveKDF(nonce, bytes(passwd, "ascii"), 64)
    keySrc = deriveKDF(nonce, passwd, 64)
    key = keySrc[:32]
    
    cc = AESGCM(key)
    enc = cc.encrypt(nonce, bmsg, None)

    of = io.BytesIO()
    of.write(_NONCE_LEN)
    of.write(nonce)
    of.write(enc)

    of.seek(0)
    return of.read()

def dec(msg, passwd):
    ef = io.BytesIO(msg)
    efNonceLen = int.from_bytes(ef.read(NONCE_BYTELEN), "little")
    efNonce = ef.read(efNonceLen)
    efEnc = ef.read()

    # keySrc = deriveKDF(efNonce, bytes(passwd, "ascii"), 64)
    keySrc = deriveKDF(efNonce, passwd, 64)
    key = keySrc[:32]

    cc = AESGCM(key)
    dmsg = cc.decrypt(efNonce, efEnc, None)

    return dmsg
