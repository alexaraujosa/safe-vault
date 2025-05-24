import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from tempfile import NamedTemporaryFile, mkdtemp
import shutil


class Keystore:
    def __init__(self, tmpCertFile, tmpKeyFile, tmp_dir):
        self.tmpCertFile = tmpCertFile
        self.tmpKeyFile = tmpKeyFile
        self.tmp_dir = tmp_dir

    def getCertFile(self):
        return self.tmpCertFile.name

    def getKeyFile(self):
        return self.tmpKeyFile.name

    @classmethod
    def load(cls, ksPath) -> 'Keystore':
        # print("Attempting to load keystore:", ksPath)
        try:
            with open(ksPath, mode="rb") as skfile:
                (pkey, cert, acerts) = pkcs12.load_key_and_certificates(skfile.read(), None)
                if pkey is None or cert is None:
                    print("Invalid keystore.")
                    exit(1)

                tmp_dir = mkdtemp(prefix="keystore_", dir=".")
                tmpKeyFile = NamedTemporaryFile(delete=False, dir=tmp_dir, suffix=".key")
                tmpKeyFile.write(pkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
                tmpKeyFile.flush()

                tmpCertFile = NamedTemporaryFile(delete=False, dir=tmp_dir, suffix=".pem")
                tmpCertFile.write(cert.public_bytes(Encoding.PEM))
                for ca in acerts:
                    tmpCertFile.write(ca.public_bytes(Encoding.PEM))
                tmpCertFile.flush()

                # print("TMP DIR:", tmp_dir)
                # print("TMP KEY FILE:", tmpKeyFile.name)
                # print("TMP CERT FILE:", tmpCertFile.name)

                return Keystore(tmpCertFile, tmpKeyFile, tmp_dir)
        except Exception as e:
            print(f"Error loading keystore: {e}")
            exit(1)

    def cleanup(self):
        self.tmpCertFile.close()
        self.tmpKeyFile.close()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
