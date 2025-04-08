import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from tempfile import NamedTemporaryFile

class Keystore:
    def __init__(self, tmpFile):
        self.tmpFile = tmpFile

    def getCertFile(self):
        return self.tmpFile.name

    @classmethod
    def load(cls, ksPath):
        print("Attempting to load keystore:", ksPath)
        with open(ksPath, mode="rb") as skfile:
            (pkey, cert, acerts) = pkcs12.load_key_and_certificates(skfile.read(), None)
            if (pkey == None or cert == None):
                print("Invalid keystore.")
                exit(1)

            tmpFile = NamedTemporaryFile("w+b", suffix=".pem")
            tmpFile.write(pkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
            tmpFile.write(cert.public_bytes(Encoding.PEM))
            for ca in acerts:
                tmpFile.write(ca.public_bytes(Encoding.PEM))
            tmpFile.flush()

            print("TMP FILE:", tmpFile.name)
            
            return Keystore(tmpFile)