# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import io
import os
import asyncio
# from cryptography.hazmat.primitives import hashes, hmac
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pbenc_aes_gcm import enc, dec
from packets.BasePacket import BasePacket, PacketKind
from packets.ECDHPacket import ECDHHandshakePacket
from packets.MessagePacket import MessagePacket

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

NONCE_LEN = 16
NONCE_BYTELEN = 1
_NONCE_LEN = NONCE_LEN.to_bytes(NONCE_BYTELEN, "little")
passwd = "Test"

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0

        self.secret = None
        self.privateKey = None

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        #
        # ALTERAR AQUI COMPORTAMENTO DO SERVIDOR
        #        
        # txt = msg.decode()
        print('%d : RAW %r' % (self.id, msg))
        bmsg = io.BytesIO(msg)
        phead = BasePacket.readHeader(bmsg)
        print("PACKET HEADER:", phead)

        match(phead["kind"]):
            case PacketKind.ECDH_HANDSHAKE:
                packet = ECDHHandshakePacket.deserialize(bmsg)
                self.privateKey = ECDHHandshakePacket.makePrivateKey()
                self.secret = ECDHHandshakePacket.exchange(self.privateKey, packet.pkey, packet.nonce)

                print(f"{self.id} HS SECRET: {self.secret}")

                nPacket = ECDHHandshakePacket(self.privateKey.public_key(), packet.nonce)
                return nPacket.serializeBytes()
                pass
            case PacketKind.MESSAGE:
                packet = MessagePacket.deserialize(bmsg, self.secret)
                print('%d : %r' % (self.id, packet.msg))
                new_msg = packet.msg.upper()

                if len(new_msg) <= 0: return None

                npacket = MessagePacket(new_msg, self.secret)
                emsg = npacket.serialize()
                emsg.seek(0)
                # emsg = enc(new_msg, passwd)
                return emsg.read()
            case _:
                print(f"Unsupported packet received: {phead['kind']}")
                return None

        # txt = dec(msg, passwd)
        # print('%d : %r' % (self.id,txt))
        # new_msg = txt.upper()
        # #
        # # return new_msg if len(new_msg) > 0 else None
        # if len(new_msg) <= 0: return None

        # emsg = enc(new_msg, passwd)
        # return emsg




        # s = io.BytesIO()
        # packet = packets.MessagePacket.MessagePacket(new_msg)
        # packet.serialize(s)
        # s.seek(0)

        # print("PACKET:", packet, s.read())
        # s.seek(0)

        # return s.read()

#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while True:
        # print(f"HE DATA: {data}")
        if not data: continue
        if data[:1]==b'\n': break

        try:
            data = srvwrk.process(data)
            if not data: break
        except BaseException as e:
            print(e)
            break

        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()
