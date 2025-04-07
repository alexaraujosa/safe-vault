import os
import ssl
import socket
import argparse
from cryptography import x509
from ssiproject.common.keystore import Keystore
from ssiproject.common.packets.DiePacket import DiePacket
from ssiproject.common.packets.HelloPacket import HelloPacket
from ssiproject.common.packets.ResultPacket import ResultPacket
from ssiproject.common.packets.BasePacket import BasePacket, PacketKind

_IGNORE_SIG = "__IGNORE__"

def handlePacket(s: ssl.SSLSocket):
    pSigStatus = BasePacket.readSigBytesNoFail(s)
    if (pSigStatus > 0): return None

    phead = BasePacket.readHeaderNoSig(s)
    # print("PACKET HEADER:", phead)
    print(f"📩 Received: {phead['kind']}")

    match(phead["kind"]):
        case PacketKind.HELLO:
            print("Got hello from server.")
            packet = DiePacket("You should KYS. NOW!")
            return packet
        case PacketKind.DIE:
            packet = DiePacket.deserialize(phead, s)
            print(f"Shutdown notice: {packet.msg}")
            return None
        case PacketKind.OP_RESULT:
            packet = ResultPacket.deserialize(phead, s)
            print(packet.resultType, packet.operationId)
            print(packet.format())
            return _IGNORE_SIG
        case _:
            print(f"Unsupported packet received: {phead['kind']}")
            return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser("client")
    parser.add_argument("--cert", type=str, required=True, help="Path to the server's CA certificate")
    parser.add_argument("--port", type=int, required=False, default=8443, help="The port for the client to connect to")
    parser.add_argument("keystore", type=str, help="Path to the client's keystore file")
    args = parser.parse_args()

    HOST = "127.0.0.1"
    PORT = args.port

    cks = Keystore.load(args.keystore)

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile=cks.getCertFile())
    context.load_verify_locations(cafile=args.cert)

    # Connect to the server
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print(f"✅ Connected securely to {HOST}:{PORT}")
            # ssock.sendall(b"Hello from Client!")
            # data = ssock.recv(1024)
            # print(f"📩 Received: {data.decode()}")

            packet = HelloPacket().setOperationId(123)
            bts = packet.serializeBytes()
            print("BTS:", bts)
            ssock.sendall(bts)

            while ((ret := handlePacket(ssock)) != None):
                if (ret == _IGNORE_SIG): continue
                print("RET PACKET:", ret)
                bts = ret.serializeBytes()
                print("RET PACKET BYTES:", bts)
                sendret = ssock.sendall(bts)
                print("RET SEND RES:", sendret)
                pass

            try:
                ssock._check_connected()
                ssock.shutdown(socket.SHUT_RDWR)
                ssock.close()
            except OSError:
                pass

