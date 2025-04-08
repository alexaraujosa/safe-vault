#!/usr/bin/env python3

# https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams

import asyncio
import common

conn_cnt = 0


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """

    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.dh_params = common.generate_dh_parameters()
        self.private_key, self.public_key = common.generate_dh_keys(self.dh_params)
        self.shared_key = None

    async def key_exchange(self, writer, reader):
        # Receive client's public key
        client_pub_key_data = await reader.read(common.max_msg_size)
        client_pub_key = common.deserialize_public_key(client_pub_key_data)

        # Send server's public key
        writer.write(common.serialize_public_key(self.public_key))
        await writer.drain()

        # Derive shared key
        self.shared_key = common.derive_shared_key(self.private_key, client_pub_key)

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1

        if self.shared_key:
            plaintext = common.decrypt(msg, self.shared_key).decode()
        else:
            plaintext = msg.decode()

        print('%d : %r' % (self.id, plaintext))
        new_msg = plaintext.upper().encode()

        return new_msg if len(new_msg) > 0 else None


# Funcionalidade Cliente/Servidor

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)

    # Exchange keys
    await srvwrk.key_exchange(writer, reader)

    data = await reader.read(common.max_msg_size)
    while True:
        if not data:
            continue
        if data[:1] == b'\n':
            break
        data = srvwrk.process(data)
        if not data:
            break
        writer.write(data)
        await writer.drain()
        data = await reader.read(common.max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', common.conn_port)
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
