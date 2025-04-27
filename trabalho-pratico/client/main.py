#!/usr/bin/env python3

import sys
import ssl
import shlex
import socket
import argparse
import readline
import traceback
from cryptography import x509

# from client.command    import process_command  # TODO import this
from common.validation import is_valid_file
from common.keystore   import Keystore

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
    parser.add_argument("--cert", type=str, required=True, help="Path to the server's CA certificate")
    parser.add_argument("--port", type=int, required=False, default=8443, help="The port for the client to connect to")
    parser.add_argument("--keystore", type=str, help="Path to the client's keystore file")
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

                setup_readline()

                doubleSIGINT = False
                while True:
                    command = ""
                    try:
                        command = input("> ").strip()
                        if not command:
                            continue

                        readline.add_history(command)
                    except KeyboardInterrupt:
                        if (not doubleSIGINT):
                            print("To exit, press CTRL + C again or type 'exit'.")
                            doubleSIGINT = True
                            continue
                        else:
                            print()
                            break
                    except EOFError:
                        break

                    doubleSIGINT = False
                    args = shlex.split(command)
                    print(f"Arguments: {args}")

                    if args[0] == "exit":
                        break

                    try:
                        # TODO: Actually process packets to and from the server.
                        # packet = process_command(args)
                        ssock.send(bytes(command, "utf-8"))
                        res = ssock.recv(1024)
                        print(f"--> {res}")
                    except Exception:
                        print("❌ Error on packet serialization.")
                        traceback.print_exc()
                        continue

                ssock.close()
    except ssl.SSLCertVerificationError:
        print("❌ Peer is not a valid server.")
    except Exception:
        print("❌ Error on client socket.")
        traceback.print_exc()
        sys.exit(1)

    print("\nExiting...")


if __name__ == "__main__":
    main()
