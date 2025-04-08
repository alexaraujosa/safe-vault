import os
import sys
import ssl
import socket
import argparse
import traceback
from pprint import pprint
from cryptography import x509
from ssiproject.common.keystore import Keystore
from ssiproject.common.packets.DiePacket import DiePacket
from ssiproject.common.packets.HelloPacket import HelloPacket
from ssiproject.common.packets.BasePacket import BasePacket, PacketKind
from ssiproject.common.packets.ResultPacket import ResultPacket, ResultType

_IGNORE_SIG = "__IGNORE__"

def extractClient(cert):
    subject = cert.subject

    for attr in subject:
        if attr.oid == x509.NameOID.PSEUDONYM: return attr.value
    return None

def processClient(connstream):
    # phead = BasePacket.readHeader(connstream)
    pSigStatus = BasePacket.readSigBytesNoFail(connstream)
    if (pSigStatus > 0): return None

    phead = BasePacket.readHeaderNoSig(connstream)
    print(f"📩 Received: {phead['kind']}")

    client_cert = connstream.getpeercert(binary_form=True)

    if client_cert:
        cert_obj = x509.load_der_x509_certificate(client_cert)
        userId = extractClient(cert_obj)
        if (userId == None):
            print("❌ User ID not provided.")
            # TODO: Truly authenticate user
            return

        print(f"✅ Authenticated User: {userId}")

        # data = connstream.recv(1024)
        # print("📩 Received:", data.decode())
        # connstream.sendall(b"KYS from Server.")

        match(phead["kind"]):
            case PacketKind.HELLO:
                print("Got hello from client.")

                # opPacket = ResultPacket(phead["operationId"], ResultType.SUCCESS)
                opPacket = ResultPacket(ResultType.ERROR, "Guess I'll die.").setOperationId(phead["operationId"])
                connstream.sendall(opPacket.serializeBytes())

                packet = HelloPacket()
                bts = packet.serializeBytes()
                print("BTS:", bts)
                connstream.sendall(bts)

                return _IGNORE_SIG
            case PacketKind.DIE:
                print("Client thinks they're fucking funny.")

                packet = DiePacket("You fucking wish.")
                bts = packet.serializeBytes()
                connstream.sendall(bts)
                return None
            case _:
                print(f"Unsupported packet received: {phead['kind']}")
                return None
    else:
        print("❌ Could not extract client data.")

def startServer(serverKeystore, caCert, port = 8843):
    # PORT = 8443

    sks = Keystore.load(serverKeystore)

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile=sks.getCertFile())
    context.load_verify_locations(cafile=caCert)
    context.verify_mode = ssl.CERT_REQUIRED

    # Start server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    # server_socket.bind(("127.0.0.1", port))
    # server_socket.listen(5)

    server = context.wrap_socket(server_socket, server_side=True)
    server.bind(("127.0.0.1", port))
    server.listen(5)
    print(f"Server listening on port {port}")
        
    while True:
        try:
            print("READING")
            conn, addr = server.accept()
            # connstream = context.wrap_socket(conn, server_side=True)
            print(f"🔗 Connection from {addr} established with mutual authentication.")

            while True:
                try:
                    if ((ret := processClient(conn)) == None):
                        if (ret == _IGNORE_SIG): continue

                        try:
                            print(f"🛑 Shutting down client from {addr}")
                            conn._check_connected()
                            conn.shutdown(socket.SHUT_RDWR)
                            conn.close()
                            break
                        except OSError:
                            print(f"🚧 Client connection from {addr} died before server could close.")
                            break
                except BaseException:
                    print(f"❌ Unknown error occured while processing client from {addr}:")
                    traceback.print_exc()
                    # exit(1)
                    # TODO: Send response back to client.
                # finally:
                    # connstream.shutdown(socket.SHUT_RDWR)
                    # connstream.close()
        except ssl.SSLError:
            print("❌ SLL Error occured while establishing connection:")
            traceback.print_exc()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("server")
    parser.add_argument("--cert", type=str, required=True, help="Path to the server's CA certificate")
    parser.add_argument("--keystore", type=str, required=True, help="Path to the server's keystore file")
    parser.add_argument("--port", type=int, required=False, default=8443, help="The port for the server to listen to")
    args = parser.parse_args()

    startServer(args.keystore, args.cert, args.port)
