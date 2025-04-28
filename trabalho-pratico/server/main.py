#!/usr/bin/env python3

import sys
import ssl
import socket
import argparse
import traceback
import threading
from cryptography import x509

from common.keystore   import Keystore
from common.validation import is_valid_file
from server.config     import Config
from server.operations import Operations
from server.handler    import process_request

CONFIG_PATH = "server/config.json"
VAULT_PATH = "server/vault"


def extract_user_id(cert):
    subject = cert.subject

    for attr in subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            return attr.value
    return None


def handleClient(operations, conn: ssl.SSLSocket, addr):
    print(f"🔗 Connection from {addr} established with mutual authentication.")

    try:
        # This following section is more of a trace than anything, tbh.
        # New users are just added to the database, so I guess it's just a way to extract the user id, ig.
        peerCert = conn.getpeercert(binary_form=True)
        if peerCert:
            peerCertObj = x509.load_der_x509_certificate(peerCert)
            # Extract common name
            user_id = extract_user_id(peerCertObj)
            if (not user_id):
                print("❌ Cannot extract user ID from certificate.")
                conn.close()
                return

            operations.authenticate_user(user_id)
            print(f"✅ Authenticated user: {user_id}")

        _died = False
        while True:
            try:
                packet_data = conn.recv()
                if not packet_data:
                    break

                print(f"📦 Received packet from {addr}")

                # TODO lock other threads from accessing the operations object
                process_request(operations, user_id, conn, packet_data)
            except ssl.SSLEOFError:
                print(f"🚧 Client connection from {addr} died before server could close it.")
                _died = True
                break
            except Exception:
                print(f"❌ Error with connection from {addr}.")
                traceback.print_exc()
                break

        if (not _died):
            print(f"🔚 Closing connection from {addr}")
        conn.close()
    except Exception:
        print(f"❌ Error on socket from {addr}.")
        traceback.print_exc()


def main():
    # Command line arguments
    parser = argparse.ArgumentParser("server")
    parser.add_argument("--cert",     type=str, required=True,                       help="Path to server's CA certificate.")
    parser.add_argument("--keystore", type=str, required=True,                       help="Path to server's keystore file.")
    parser.add_argument("--port",     type=int, required=False, default=8443,        help="Port to server listen on.")
    parser.add_argument("--config",   type=str, required=False, default=CONFIG_PATH, help="Path to server's config file.")
    parser.add_argument("--vault",    type=str, required=False, default=VAULT_PATH,  help="Path to server's vault directory.")
    args = parser.parse_args()

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
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Load .p12 file
        sks = Keystore.load(p12_file)
        # Load server certificate and private key
        context.load_cert_chain(certfile=sks.getCertFile(), keyfile=sks.getKeyFile())
        # Load trustable CA
        context.load_verify_locations(cafile=ca_cert_file)
        # Verify if the client certificate is signed by a trusted CA
        context.verify_mode = ssl.CERT_REQUIRED

        # !!!!! DEBUG ONLY - Dump keylog file !!!!!
        # context.keylog_filename = "VAULT_SERVER_KL.log"
    except Exception:
        print("❌ Failed to set up SSL context.")
        traceback.print_exc()
        sys.exit(1)

    try:
        # Load the JSON config file
        config = Config(args.config)

        # Initalize server operations class
        operations = Operations(config.config, args.vault)
    except Exception:
        print("Failed to set up server configuration.")
        traceback.print_exc()

    # Connection
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_side=True) as ssock:
                ssock.bind(("127.0.0.1", port))
                ssock.listen()
                print(f"📡 Server listening on port {port}")

                while True:
                    try:
                        conn, addr = ssock.accept()
                        client_thread = threading.Thread(target=handleClient, args=(operations, conn, addr))
                        client_thread.start()
                        # print(f"Active connections: {threading.active_count() - 1}")
                    except ssl.SSLCertVerificationError:
                        print("🚧 Client attempted to establish connection with an expired certificate.")
                    except ssl.SSLError:
                        print("❌ SLL Error occured while establishing connection.")
                        traceback.print_exc()
                    except KeyboardInterrupt:
                        # Server is closing. Don't panic.
                        break
    except PermissionError:
        print("❌ Permission denied.")
        sys.exit(1)
    except OSError as e:
        if e.errno == 98:
            print(f"❌ Port {port} already in use.")
        else:
            print(f"❌ Failed to bind socket: {e}")
        sys.exit(1)
    except Exception:
        traceback.print_exc()
        sys.exit(1)

    # Save the config file
    try:
        config.save(config=operations.config)
    except Exception as e:
        print(f"Failed to save server config: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
