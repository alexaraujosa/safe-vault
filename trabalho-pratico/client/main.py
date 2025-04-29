#!/usr/bin/env python3

import sys
import ssl
import shlex
import socket
import argparse
import readline
import traceback
from cryptography import x509

from common.keystore   import Keystore
from common.validation import is_valid_file
from client.encryption import RSA
from client.handler    import process_command

SERVER_ID = "VAULT_SERVER"
HISTORY_SIZE = 100


def extractSubjectId(cert):
    subject = cert.subject

    for attr in subject:
        if attr.oid == x509.NameOID.PSEUDONYM:
            return attr.value
    return None


def setup_readline():
    readline.set_history_length(HISTORY_SIZE)
    readline.set_auto_history(False)
    readline.parse_and_bind("tab: complete")
    readline.parse_and_bind("set blink-matching-paren on")


def main():
    parser = argparse.ArgumentParser("client")
    parser.add_argument("--cert",     type=str, required=True,                help="Path to the server's CA certificate")
    parser.add_argument("--keystore", type=str, required=True,                help="Path to the client's keystore file")
    parser.add_argument("--port",     type=int, required=False, default=8443, help="The port for the client to connect to")
    args = parser.parse_args()

    # Extract and validate arguments
    ca_cert_file = args.cert
    p12_file = args.keystore
    port = args.port

    if not (1 <= port <= 65535):
        print("❌ Invalid port number. Must be between 1 and 65535.")
        sys.exit(1)

    for file in [ca_cert_file, p12_file]:
        if not is_valid_file(file):
            print(f"❌ Invalid file: {file}.")
            sys.exit(1)

    # Extract public key and private key from PKCS#12 file
    try:
        client_private_key, client_public_key = RSA.load_keys_from_p12(p12_file)
    except Exception as e:
        print(f"❌ Failed to load PKCS#12 file: {e}")
        sys.exit(1)

    # SSL Context
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Load .p12 file
        cks = Keystore.load(p12_file)
        # Load client certificate and private key
        context.load_cert_chain(certfile=cks.getCertFile(), keyfile=cks.getKeyFile())
        # Load trustable CA
        context.load_verify_locations(cafile=ca_cert_file)
        # Verify if the server certificate is signed by a trusted CA
        context.verify_mode = ssl.CERT_REQUIRED

        # There are two options to check if the peer connection is in fact the server or just a valid client certificate
        # One of them is by setting this option to True, which will order the ssl module to ensure that the
        # certificate on the response's Subject's COMMON_NAME property equals the defined server hostname.
        # The other method is by setting this option to False and allow the peer id extraction path to fail.
        # Either should do the trick. If you prefer option one, you can also opt to keep the second, as a way to double
        # check the server certificate.
        context.check_hostname = True
    except Exception:
        print("❌ Failed to set up SSL context.")
        traceback.print_exc()
        sys.exit(1)

    # Connection
    try:
        with socket.create_connection(("127.0.0.1", port)) as sock:
            with context.wrap_socket(sock, server_hostname="SSI Vault Server") as ssock:
                print(f"✅ Connected securely to 127.0.0.1:{port}")
                print(f"Socket Version: {ssock.version()}")

                peerCert = ssock.getpeercert(binary_form=True)
                if peerCert:
                    peerCertObj = x509.load_der_x509_certificate(peerCert)
                    serverId = extractSubjectId(peerCertObj)

                    if (serverId is None or serverId != SERVER_ID):
                        print("❌ Invalid Server ID.")
                        raise Exception

                    print(f"✅ Authenticated Server: {serverId}")
                else:
                    print("❌ Failed to get peer certificate.")
                    raise Exception

                # TODO wait server response (USER_ID_ALREADY_EXISTS | SUCCESS)

                setup_readline()

                doubleSIGINT = False
                while True:
                    command = ""
                    try:
                        command = input("> ").strip()
                        if not command:
                            continue
                    except KeyboardInterrupt:
                        if (not doubleSIGINT):
                            print("To exit, press CTRL + C again or type 'exit'.")
                            doubleSIGINT = True
                            continue
                        print()
                        break
                    except EOFError:
                        break

                    readline.add_history(command)
                    doubleSIGINT = False
                    args = shlex.split(command)

                    if args[0] == "exit":
                        break

                    try:
                        process_command(sock, ssock, args,
                                        client_private_key, client_public_key)
                    except ValueError as e:
                        print(e)
                    except ssl.SSLError:
                        print("❌ Error on packet serialization.")
                        traceback.print_exc()
                    except Exception as e:
                        print(f"❌ Error on client socket: {e}")
                        traceback.print_exc()
                        sys.exit(1)

                ssock.close()
    except ssl.SSLCertVerificationError:
        print("❌ Peer is not a valid server.")
    except ConnectionRefusedError:
        print(f"❌ Connection refused. Is the server running on port {port}?")
        sys.exit(1)
    except PermissionError:
        print("❌ Permission denied.")
        sys.exit(1)
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
