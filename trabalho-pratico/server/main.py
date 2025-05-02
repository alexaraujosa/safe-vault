#!/usr/bin/env python3

import sys
import ssl
import socket
import argparse
import traceback
import threading
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from common.exceptions import UserExists
from common.keystore   import Keystore
from common.validation import is_valid_file
from common.packet     import read_fully, create_packet, CommandType, LogsStatus
from server.config     import Config
from server.operations import Operations, get_current_timestamp
from server.handler    import process_request
from server.logs       import Logs

from common.debug import (
    G_SERVER_DEBUG as G_DEBUG,
    G_SERVER_CONFIG_DEBUG as G_CONFIG_DEBUG,
    trace
)

# Constants
DEFAULT_CA   = "assets/certs/VAULT_CA.crt"  # Default path for server CA certificate
DEFATULT_P12 = "assets/keystores/VAULT_SERVER.p12"  # Default path for server keystore
CONFIG_PATH  = "server/config.json"
LOGS_PATH    = "server/logs.json"
VAULT_PATH   = "server/vault"


def extract_user_id(cert):
    subject = cert.subject

    for attr in subject:
        if attr.oid == x509.NameOID.PSEUDONYM:
            return attr.value
    return None


def handleClient(operations, conn: ssl.SSLSocket, addr, config, process_lock):
    print(f"🔗 Connection from {addr} established with mutual authentication.")

    try:
        # This following section is more of a trace than anything, tbh.
        # New users are just added to the database, so I guess it's just a way to extract the user id, ig.
        peerCert = conn.getpeercert(binary_form=True)
        if not peerCert:
            print("❌ No peer certificate found.")
            conn.close()
            return

        peerCertObj = x509.load_der_x509_certificate(peerCert)
        # Extract common name
        user_id = extract_user_id(peerCertObj)
        if (not user_id):
            print("❌ Cannot extract user ID from certificate.")
            conn.close()
            return

        # Authenticate user and create account if not found
        try:
            public_key = peerCertObj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with process_lock:
                operations.create_user(user_id, base64.b64encode(public_key).decode("utf-8"))
                operations.logs["users"][user_id] = []
                operations.logs["users"][user_id].append({
                    "executor": "system",
                    "time": get_current_timestamp(),
                    "status": LogsStatus.SUCCESS.value,
                    "command": "create user"
                })
            print(f"✅ User {user_id} account created.")

            # Send welcome packet
            conn.send(create_packet(CommandType.AUTH_WELCOME.value))
        except UserExists:
            with process_lock:
                config_client_public_key = base64.b64decode(config.config["users"][user_id]["public_key"])
            if config_client_public_key == public_key:
                # Send welcome back packet
                operations.logs["users"][user_id].append({
                    "executor": "system",
                    "time": get_current_timestamp(),
                    "status": LogsStatus.SUCCESS.value,
                    "command": "authenticate user"
                })
                conn.send(create_packet(CommandType.AUTH_WELCOME_BACK.value))
                print(f"✅ User {user_id} authenticated.")
            else:
                # Send user id already took packet
                operations.logs["users"][user_id].append({
                    "executor": "system",
                    "time": get_current_timestamp(),
                    "status": LogsStatus.FAILURE.value,
                    "command": "authenticate user"
                })
                conn.send(create_packet(CommandType.AUTH_USER_ALREADY_TOOK.value))
                print(f"❌ Attempt to authenticate as {user_id}, but detected different public key!")

        except ValueError:
            conn.send(create_packet(CommandType.AUTH_FAIL.value))
            print(f"🚧 Invalid user ID: {user_id}.")
            exit(1)

        # Save the config in case a new user was created
        if G_CONFIG_DEBUG:
            with process_lock:
                config.save(config=operations.config)

        _died = False
        while True:
            try:
                # packet_data = conn.recv()
                packet_data = read_fully(conn, G_DEBUG)
                if not packet_data:
                    break

                print(f"📦 Received packet from {addr}")
                trace("PACKET LEN:", len(packet_data), g_debug=G_DEBUG)
                trace(packet_data, g_debug=G_DEBUG)

                with process_lock:
                    process_request(operations, user_id, conn, packet_data)

                    # DEBUG update the config file on every operation
                    if G_CONFIG_DEBUG:
                        config.save(config=operations.config)
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
    parser.add_argument("--cert",        type=str, required=False, default=DEFAULT_CA,   help="Server CA certificate file.")
    parser.add_argument("--keystore",    type=str, required=False, default=DEFATULT_P12, help="Server keystore file.")
    parser.add_argument("--port",        type=int, required=False, default=8443,         help="Port number to listen on.")
    parser.add_argument("--config",      type=str, required=False, default=CONFIG_PATH,  help="Config file path.")
    parser.add_argument("--vault",       type=str, required=False, default=VAULT_PATH,   help="Vault file path.")
    parser.add_argument("--logs",        type=str, required=False, default=LOGS_PATH,    help="Logs file path.")
    parser.add_argument("--debug", "-d",           required=False, default=False,        help="Enable debug mode.", action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    # Validate command line arguments
    global G_DEBUG
    G_DEBUG = args.debug

    if not (1 <= args.port <= 65535):
        print("❌ Invalid port number. Must be between 1 and 65535.")
        sys.exit(1)

    for file in [args.cert, args.keystore]:
        if not is_valid_file(file):
            print(f"❌ Invalid file: {file}.")
            sys.exit(1)

    # SSL Context
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Load .p12 file
        sks = Keystore.load(args.keystore)
        # Load server certificate and private key
        context.load_cert_chain(certfile=sks.getCertFile(), keyfile=sks.getKeyFile())
        # Load trustable CA
        context.load_verify_locations(cafile=args.cert)
        # Verify if the client certificate is signed by a trusted CA
        context.verify_mode = ssl.CERT_REQUIRED

        # !!!!! DEBUG ONLY - Dump keylog file !!!!!
        # context.keylog_filename = "VAULT_SERVER_KL.log"
    except Exception:
        print("❌ Failed to set up SSL context.")
        traceback.print_exc()
        sks.cleanup()
        sys.exit(1)
    finally:
        sks.cleanup()

    try:
        # Load the JSON config file
        config = Config(args.config)

        # Initialize server logs
        logs = Logs(args.logs)

        # Initialize server operations class
        operations = Operations(config.config, logs.logs, args.vault)

        # Create process lock
        process_lock = threading.Lock()
    except Exception:
        print("Failed to set up server configuration.")
        traceback.print_exc()

    # Connection
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_side=True) as ssock:
                ssock.bind(("127.0.0.1", args.port))
                ssock.listen()
                print(f"📡 Server listening on port {args.port}")

                while True:
                    try:
                        conn, addr = ssock.accept()
                        client_thread = threading.Thread(target=handleClient, args=(operations, conn, addr, config, process_lock))
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
            print(f"❌ Port {args.port} already in use.")
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

    # Save log file
    try:
        logs.save(logs=operations.logs)
    except Exception as e:
        print(f"Failed to save log file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
