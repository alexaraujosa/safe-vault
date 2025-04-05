#!/usr/bin/env python3

# https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams

import asyncio
import common


class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """

    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        print('Received (%d): %r' % (self.msg_cnt, msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        new_msg = common.encrypt(new_msg, "passphrase")
        return new_msg if len(new_msg) > 0 else None


# Funcionalidade Cliente/Servidor

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', common.conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(common.max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()


def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
