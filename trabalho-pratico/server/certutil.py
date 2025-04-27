import os
import argparse
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12
# from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ============== Configuration ==============
CA_SUBJECT = {
    "C": "PT",
    "ST": "Minho",
    "L": "Braga",
    "O": "Universidade do Minho",
    "OU": "SSI VAULT SERVICE",
    "CN": "SSI VAULT SERVICE CA",
    "PSEUDONYM": "VAULT_CA"
}
CERT_SUBJECT_TEMPLATE = {
    "C": "PT",
    "ST": "Minho",
    "L": "Braga",
    "O": "Universidade do Minho",
    "OU": "SSI VAULT SERVICE"
}
# ============== Configuration ==============

# ============== Functions ==============
NAMEOID_MAPPER = {
    "C": "COUNTRY_NAME",
    "ST": "STATE_OR_PROVINCE_NAME",
    "L": "LOCALITY_NAME",
    "O": "ORGANIZATION_NAME",
    "OU": "ORGANIZATIONAL_UNIT_NAME",
    "CN": "COMMON_NAME",
    "PSEUDONYM": "PSEUDONYM",
}


def generatePrivateKey():
    # Using Elliptic Curve
    # return ec.generate_private_key(
    #     ec.SECP256R1(),
    #     backend=default_backend()
    # )
    # Using RSA (same as client.encryption module)
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def generateX509Name(attributes):
    return x509.Name([
        x509.NameAttribute(getattr(NameOID, NAMEOID_MAPPER[k]), v) for k, v in attributes.items()
    ])


def generateCACert(key, subjectInfo, nValidBefore=None, nValidAfter=None):
    subject = generateX509Name(subjectInfo)

    if (nValidBefore is None):
        nValidBefore = datetime.datetime.utcnow()
    if (nValidAfter is None):
        nValidAfter = datetime.datetime.utcnow() + datetime.timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nValidBefore)
            .not_valid_after(nValidAfter)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())
    )

    return cert


def generateSubjectCert(caCert, caKey, key, commonName, subjectId, nValidBefore=None, nValidAfter=None):
    subjectInfo = CERT_SUBJECT_TEMPLATE.copy()
    subjectInfo["CN"] = commonName
    subjectInfo["PSEUDONYM"] = subjectId

    if (nValidBefore is None):
        nValidBefore = datetime.datetime.utcnow()
    if (nValidAfter is None):
        nValidAfter = datetime.datetime.utcnow() + datetime.timedelta(days=365)

    subject = generateX509Name(subjectInfo)
    cert = (
        x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(caCert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nValidBefore)
            .not_valid_after(nValidAfter)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key=caKey, algorithm=hashes.SHA256(), backend=default_backend())
    )

    return cert


def generatePKCS12(name, cert, key, caCert):
    # p12 = crypto.PKCS12()
    # p12.set_privatekey(crypto.PKey.from_cryptography_key(key))
    # p12.set_certificate(crypto.X509.from_cryptography(cert))
    # p12.set_ca_certificates([crypto.X509.from_cryptography(caCert)])

    # return p12.export(passphrase=None)

    return pkcs12.serialize_key_and_certificates(name, key, cert, [caCert], serialization.NoEncryption())


def readPEM(filename, pemType):
    with open(filename, "rb") as f:
        if pemType == "key":
            return serialization.load_pem_private_key(f.read(), None)
        elif pemType == "cert":
            return x509.load_pem_x509_certificate(f.read())


def writePEM(filename, data, pemType):
    with open(filename, "wb") as f:
        if pemType == "key":
            f.write(data.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        elif pemType == "cert":
            f.write(data.public_bytes(serialization.Encoding.PEM))
# ============== Functions ==============


# === Example Usage ===
if __name__ == "__main__":
    # # CA key and cert
    # ca_key = create_key()
    # ca_cert = generateCACert(ca_key, CA_SUBJECT)

    # # Server/client key and cert
    # server_key = create_key()
    # server_cert = generateSubjectCert(ca_cert, ca_key, server_key, "server.local")

    # # Export to PKCS12
    # pkcs12_data = generatePKCS12("server", server_cert, server_key, ca_cert)

    # # Save to file
    # with open("server_keystore.p12", "wb") as f:
    #     f.write(pkcs12_data)

    # print("✅ CA cert, server cert, and PKCS12 keystore generated.")

    parser = argparse.ArgumentParser(
        description="A utility for the generation of self-signed "
                    "Certification Authorities and keystores issued by said CAs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # CA generation
    genCACommand = subparsers.add_parser("genca", help="Generate a new CA certificate and private key.")
    genCACommand.add_argument("--out-dir", required=True, type=str)

    # Cert generation
    genCertCommand = subparsers.add_parser("genstore", help="Generate signed cert and PKCS12")
    genCertCommand.add_argument("--out-dir",          required=True,  type=str)
    genCertCommand.add_argument("--ca-key",           required=True,  type=str)
    genCertCommand.add_argument("--ca-cert",          required=True,  type=str)
    genCertCommand.add_argument("--name",             required=True,  type=str)
    genCertCommand.add_argument("--id",               required=True,  type=str)
    genCertCommand.add_argument("--not-valid-before", required=False, type=str)
    genCertCommand.add_argument("--not-valid-after",  required=False, type=str)

    args = parser.parse_args()

    match(args.command):
        case "genca":
            os.makedirs(args.out_dir, exist_ok=True)

            caKey = generatePrivateKey()
            caCert = generateCACert(caKey, CA_SUBJECT)

            writePEM(os.path.join(args.out_dir, "VAULT_CA.pem"), caKey, "key")
            writePEM(os.path.join(args.out_dir, "VAULT_CA.crt"), caCert, "cert")
            print("✅ CA certificate and key saved.")
        case "genstore":
            caKey = readPEM(args.ca_key, "key")
            caCert = readPEM(args.ca_cert, "cert")

            nValidBefore = datetime.datetime.strptime(args.not_valid_before, "%d/%m/%Y") \
                if (args.not_valid_before is not None) \
                else None
            nValidAfter = datetime.datetime.strptime(args.not_valid_after, "%d/%m/%Y") \
                if (args.not_valid_after is not None) \
                else None

            key = generatePrivateKey()
            cert = generateSubjectCert(
                caCert,
                caKey,
                key,
                args.name,
                args.id,
                nValidBefore,
                nValidAfter
            )
            p12 = generatePKCS12(bytes(args.id, "utf-8"), cert, key, caCert)
            with open(os.path.join(args.out_dir, f"{args.id}.p12"), "wb") as f:
                f.write(p12)

            print(f"✅ Certificate and keystore for '{args.id}' saved.")
