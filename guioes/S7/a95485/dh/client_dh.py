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
        self.dh_params = common.generate_dh_parameters()
        self.private_key, self.public_key = common.generate_dh_keys(self.dh_params)
        self.shared_key = None

    async def key_exchange(self, writer, reader):
        # Send client's public key
        writer.write(common.serialize_public_key(self.public_key))
        await writer.drain()

        # Receive server's public key
        server_pub_key_data = await reader.read(common.max_msg_size)
        server_pub_key = common.deserialize_public_key(server_pub_key_data)

        # Derive shared key
        self.shared_key = common.derive_shared_key(self.private_key, server_pub_key)

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        print('Received (%d): %r' % (self.msg_cnt, msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        if self.shared_key:
            new_msg = common.encrypt(new_msg, self.shared_key)
        else:
            print("Shared key not established yet. Sending plaintext.")
            new_msg = new_msg
        return new_msg if len(new_msg) > 0 else None


# Funcionalidade Cliente/Servidor

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', common.conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)

    # Exchange keys
    await client.key_exchange(writer, reader)

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
