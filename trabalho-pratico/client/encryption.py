import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12


class AES_GCM:
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> dict:
        """Encrypt data with AES-GCM (256-bit key)"""
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'tag': encryptor.tag
        }

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """Decrypt AES-GCM encrypted data"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class RSA:
    @staticmethod
    def encrypt(data: bytes, public_key, label: str = None) -> bytes:
        """Encrypt data with RSA-OAEP (2048-bit or higher)"""
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label.encode() if label else None
            )
        )

    @staticmethod
    def decrypt(ciphertext: bytes, private_key, label: str = None) -> bytes:
        """Decrypt RSA-OAEP encrypted data"""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label.encode() if label else None
            )
        )

    @staticmethod
    def load_keys_from_p12(p12_path: str, password: str = None):
        """Extract both private and public keys from PKCS#12 file"""
        try:
            with open(p12_path, "rb") as f:
                private_key, cert, _ = pkcs12.load_key_and_certificates(
                    f.read(),
                    password.encode() if password else None,
                    default_backend()
                )
        except Exception as e:
            raise OSError(f"Failed to load PKCS#12 file: {e}")

        if not cert:
            raise ValueError("No certificate found in PKCS12 file")

        return private_key, cert.public_key()


if __name__ == "__main__":
    # AES-GCM example
    aes_key = os.urandom(32)  # 256-bit key
    data = b"Hello, AES-GCM!"
    encrypted_data = AES_GCM.encrypt(data, aes_key)
    decrypted_data = AES_GCM.decrypt(
        encrypted_data['ciphertext'],
        aes_key,
        encrypted_data['iv'],
        encrypted_data['tag']
    )
    print("### AES-GCM Example ###")
    print(f"Original: {data}")
    print(f"Encrypted: {encrypted_data['ciphertext'].hex()}")
    print(f"Decrypted: {decrypted_data}")
    print()

    # RSA example
    from cryptography.hazmat.primitives.asymmetric import rsa
    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    rsa_data = b"Hello, RSA!"
    encrypted_rsa_data = RSA.encrypt(rsa_data, public_key)
    decrypted_rsa_data = RSA.decrypt(encrypted_rsa_data, private_key)
    print("### RSA Example ###")
    print(f"Original: {rsa_data}")
    print(f"Encrypted: {encrypted_rsa_data.hex()}")
    print(f"Decrypted: {decrypted_rsa_data}")
    print()

    # RSA example using certificates
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 encryption.py <key.p12>")
        sys.exit(1)

    private_key, public_key = RSA.load_keys_from_p12(sys.argv[1], None)
    rsa_data = b"Hello, RSA with PKCS#12!"
    encrypted_rsa_data = RSA.encrypt(rsa_data, public_key)
    decrypted_rsa_data = RSA.decrypt(encrypted_rsa_data, private_key)
    print("### RSA Example with PKCS#12 ###")
    print(f"Original: {rsa_data}")
    print(f"Encrypted: {encrypted_rsa_data.hex()}")
    print(f"Decrypted: {decrypted_rsa_data}")
