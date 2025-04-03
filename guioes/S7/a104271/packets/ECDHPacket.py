import io
import os
from packets.BasePacket import BasePacket, PacketKind
from exceptions import PacketSerializationException 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey, DHPrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key

class ECDHHandshakePacket(BasePacket):
    KEYLEN_BYTELEN = 2
    NONCE_BYTELEN  = 4

    DERIVED_KEY_LABEL = b"SSI_SHARED_KEY"

    def __init__(self, pkey: DHPublicKey, nonce = None):
        super().__init__()
        self.kind = PacketKind.ECDH_HANDSHAKE
        self.pkey = pkey
        if (nonce == None):
            self.nonce = os.urandom(self.NONCE_BYTELEN)
        else:
            self.nonce = nonce

    def serialize(self, s: io.BytesIO = None):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        if (len(self.nonce) != self.NONCE_BYTELEN):
            raise PacketSerializationException(
                f"Nonce byte len is different than required: {len(self.nonce)} - {self.NONCE_BYTELEN}"
            )

        s.write(self.nonce)

        keybytes = self.pkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        s.write(len(keybytes).to_bytes(self.KEYLEN_BYTELEN, "little"))
        s.write(keybytes)
        
        return s

    @classmethod
    def deserialize(cls, s: io.BytesIO):
        nonce = s.read(cls.NONCE_BYTELEN)
        keylen = int.from_bytes(s.read(cls.KEYLEN_BYTELEN), "little")
        keybytes = s.read(keylen)
        pkey = load_pem_public_key(keybytes)

        return cls(pkey, nonce)

    @classmethod
    def makePrivateKey(cls) -> DHPrivateKey:
        return ec.generate_private_key(ec.SECP384R1())

    @classmethod
    def exchange(cls, ownKey: DHPrivateKey, peerKey: DHPublicKey, nonce: bytes):
        secret = ownKey.exchange(ec.ECDH(), peerKey)
        derivedKey = HKDF(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = nonce,
            info = cls.DERIVED_KEY_LABEL,
        ).derive(secret)
        
        return derivedKey