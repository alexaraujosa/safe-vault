# Common functions for the client and server and AES-GCM encryption/decryption

from os import urandom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

conn_port = 7777
max_msg_size = 9999

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


def encrypt(plaintext, passwd):
    """ Encrypts a plaintext message using AES-GCM with a derived key. """
    aad = b"authenticated but unencrypted data"

    nonce = urandom(NONCE_LEN)
    key = derivate(nonce, passwd)

    aesgcm = AESGCM(key)
    enc = aesgcm.encrypt(nonce, plaintext, aad)

    return _NONCE_LEN + nonce + enc


def decrypt(ciphertext, passwd):
    """ Decrypts a ciphertext message using AES-GCM with a derived key. """
    aad = b"authenticated but unencrypted data"

    efNonceLen = int.from_bytes(ciphertext[:NONCE_BYTELEN], "little")
    efNonce = ciphertext[NONCE_BYTELEN:NONCE_BYTELEN + efNonceLen]
    efEnc = ciphertext[NONCE_BYTELEN + efNonceLen:]

    key = derivate(efNonce, passwd)

    aesgcm = AESGCM(key)
    dec = aesgcm.decrypt(efNonce, efEnc, aad)

    return dec
