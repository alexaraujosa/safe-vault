# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import os
import io
import socket
import asyncio
# from cryptography.hazmat.primitives import hashes, hmac
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pbenc_aes_gcm import enc, dec
from packets.BasePacket import BasePacket, PacketKind
from packets.ECDHPacket import ECDHHandshakePacket
from packets.MessagePacket import MessagePacket

conn_port = 7777
max_msg_size = 9999

NONCE_BYTELEN = 1
passwd = "Test"

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0

        self.secret = None
        self.privateKey = None
        self._handshake = None

    def process(self, msg=b""):
        self.msg_cnt +=1

        print('Received raw (%d): %r' % (self.msg_cnt , msg))

        if (msg != b""):
            bmsg = io.BytesIO(msg)
            phead = BasePacket.readHeader(bmsg)
            print("PACKET HEADER:", phead)

            match(phead["kind"]):
                case PacketKind.ECDH_HANDSHAKE:
                    packet = ECDHHandshakePacket.deserialize(bmsg)
                    self.secret = ECDHHandshakePacket.exchange(self.privateKey, packet.pkey, self._handshake.nonce)

                    print(f"HS SECRET: {self.secret}")
                    return self.processMsg(None)
                case PacketKind.MESSAGE:
                    packet = MessagePacket.deserialize(bmsg, self.secret)
                    return self.processMsg(packet)
                case _:
                    print(f"Unsupported packet received: {phead['kind']}")
                    return None

        return None

    def processMsg(self, packet: MessagePacket = None):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        # self.msg_cnt +=1

        # print('Received raw (%d): %r' % (self.msg_cnt , msg))
        
        #
        # ALTERAR AQUI COMPORTAMENTO DO CLIENTE
        #


        # match (msg[0]):
        #     case 0: # Malformed
        #         return None
        #     case 1: # DH_PARAMETER_EXCHANGE

        # if (msg != b""):
        #     bmsg = io.BytesIO(msg)
        #     phead = BasePacket.readHeader(bmsg)
        #     print("PACKET HEADER:", phead)

        #     match(phead["kind"]):
        #         case PacketKind.ECDH_HANDSHAKE:
        #             packet = ECDHHandshakePacket.deserialize(bmsg)
        #             self.secret = ECDHHandshakePacket.exchange(self.privateKey, packet.pkey, self._handshake.nonce)

        #             print(f"HS: {self.secret}")
        #             pass
        #         case PacketKind.MESSAGE:
        #             packet = MessagePacket.deserialize(bmsg)
        #             print('Received (%d): %r' % (self.msg_cnt , packet.msg))
        #         case _:
        #             print(f"Unsupported packet received: {phead['kind']}")
        #             return None
            # dmsg = dec(msg, passwd)
            # print('Received (%d): %r' % (self.msg_cnt , dmsg))

        if (packet != None):
            print('Received (%d): %r' % (self.msg_cnt , packet.msg))

        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        #
        if len(new_msg) <= 0: return None

        # emsg = enc(new_msg, passwd)
        # return emsg

        s = io.BytesIO()
        packet = MessagePacket(new_msg, self.secret)
        packet.serialize(s)
        s.seek(0)

        print("PACKET:", packet, s.read())
        s.seek(0)

        return s.read()



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    # msg = client.process()

    # TODO: Initiate ECDH handshake
    client.privateKey = ECDHHandshakePacket.makePrivateKey()
    hsPacket = ECDHHandshakePacket(client.privateKey.public_key())
    client._handshake = hsPacket

    msg = hsPacket.serializeBytes()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)

        # print(f"TEC: {msg}")
        if msg:
            try:
                msg = client.process(msg)
            except BaseException as e:
                print(e)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
