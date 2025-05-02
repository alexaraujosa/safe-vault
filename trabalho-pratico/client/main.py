#!/usr/bin/env python3

import sys
import ssl
import shlex
import socket
import argparse
import readline
import traceback
from cryptography import x509
from bson import BSON

from common.keystore   import Keystore
from common.validation import is_valid_file
from common.packet     import read_fully, CommandType
from client.encryption import RSA
from client.handler    import process_command
from client.usage      import _full as full_usage

SERVER_ID = "VAULT_SERVER"
DEFAULT_CA = "assets/certs/VAULT_CA.crt"  # Default path for server CA certificate
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
    parser.add_argument("--keystore", type=str, required=True,                       help="Client's keystore file")
    parser.add_argument("--cert",     type=str, required=False, default=DEFAULT_CA,  help="Server's CA certificate file")
    parser.add_argument("--host",     type=str, required=False, default="127.0.0.1", help="Server hostname or IP address")
    parser.add_argument("--port",     type=int, required=False, default=8443,        help="Server port number")
    args = parser.parse_args()

    # Validate command line arguments
    if not (1 <= args.port <= 65535):
        print("❌ Invalid port number. Must be between 1 and 65535.")
        sys.exit(1)

    for file in [args.cert, args.keystore]:
        if not is_valid_file(file):
            print(f"❌ Invalid file: {file}.")
            sys.exit(1)

    # Extract public key and private key from PKCS#12 file
    try:
        client_private_key, client_public_key, client_cert = RSA.load_keys_from_p12(args.keystore)
    except Exception as e:
        print(f"❌ Failed to load PKCS#12 file: {e}")
        sys.exit(1)

    # SSL Context
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Load .p12 file
        cks = Keystore.load(args.keystore)
        # Load client certificate and private key
        context.load_cert_chain(certfile=cks.getCertFile(), keyfile=cks.getKeyFile())
        # Load trustable CA
        context.load_verify_locations(cafile=args.cert)
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
        cks.cleanup()
        sys.exit(1)
    finally:
        cks.cleanup()

    # Connection
    try:
        with socket.create_connection((args.host, args.port)) as sock:
            with context.wrap_socket(sock, server_hostname="SSI Vault Server") as ssock:
                print(f"✅ Connected securely to {args.host}:{args.port}")
                # print(f"Socket Version: {ssock.version()}")

                peerCert = ssock.getpeercert(binary_form=True)
                if not peerCert:
                    print("❌ Failed to get peer certificate.")
                    exit(1)

                peerCertObj = x509.load_der_x509_certificate(peerCert)
                serverId = extractSubjectId(peerCertObj)
                if serverId != SERVER_ID:
                    print("❌ Invalid Server ID.")
                    exit(1)

                print(f"✅ Server authenticated: {serverId}")

                auth_packet = BSON.decode(read_fully(ssock))
                user_id = extractSubjectId(client_cert)
                if user_id:
                    match auth_packet.get("type"):
                        case CommandType.AUTH_WELCOME.value:
                            print(f"Welcome {user_id}")
                        case CommandType.AUTH_WELCOME_BACK.value:
                            print(f"Welcome back {user_id}")
                        case CommandType.AUTH_USER_ALREADY_TOOK.value:
                            print("Authentication failed!")
                            print(f"The user id '{user_id}' already exists.\n"
                                  "Regenerate the certificate with a different user id.")
                            sys.exit(1)
                        case CommandType.AUTH_FAIL.value:
                            print(f"Invalid user id '{user_id}'.")
                            sys.exit(1)
                else:
                    print("Error on authentication, due to empty user id on the provided certificate.")
                    sys.exit(1)

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

                    if args[0] == "whoami":
                        print(user_id)
                        continue
                    elif args[0] == "help":
                        print(full_usage)
                        continue
                    elif args[0] == "exit":
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
        print(f"❌ Connection refused. Is the server running on port {args.port}?")
        sys.exit(1)
    except PermissionError:
        print("❌ Permission denied.")
        sys.exit(1)
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
