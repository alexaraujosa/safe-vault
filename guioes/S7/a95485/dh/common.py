from os import urandom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key

conn_port = 7777
max_msg_size = 9999

# DH parameters
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
G = 2


def generate_dh_parameters():
    return dh.DHParameterNumbers(P, G).parameters()


def generate_dh_keys(params):
    private_key = params.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def deserialize_public_key(data):
    return load_pem_public_key(data)


def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'dh-key-derivation',
    ).derive(shared_key)


def encrypt(plaintext, key):
    nonce = urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(ciphertext, key):
    nonce = ciphertext[:12]
    encrypted = ciphertext[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted, None)
