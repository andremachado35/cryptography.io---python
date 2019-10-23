# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import os

#biblioteca hmac\n
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
#biblioteca chacha20
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#biblioteca pbkdf2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
conn_cnt = 0
conn_port = 8888
max_msg_size = 9999
backend = default_backend()

f = open('achave.txt','wb')
# Salts should be randomly generate
salt = os.urandom(16) #random 16 bits

# derive
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)
k = kdf.derive(b"exemplodois")
keyy = bytes(k)

    #dividir key em 2
keyaes=keyy[0:16] #chave de iv
keymac=keyy[16:32] #chave de hmac


f.write(keyy)
f.close()
def encriptarcli (keyaes, iv_client,novamensagem):
    #aes com key do ficheiro e iv_ que veio da mensagem
    cipher = Cipher(algorithms.AES(keyaes),modes.CTR(iv_client), backend = backend)
    #desencriptar a mensagem
    decryptor = cipher.decryptor()
    ctpp = decryptor.update(novamensagem)
    return ctpp

def encriptarserver (keyaes, iv, ctp):
    #encriptar
    cipher = Cipher(algorithms.AES(keyaes),modes.CTR(iv), backend = backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(ctp) + encryptor.finalize()
    return ct

def hmacserver (keymac,ct):
        h = hmac.HMAC(keymac, hashes.SHA256(), backend=default_backend())
        h.update(ct)
        final = h.finalize()
        return final

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        #dividir iv do hmac do texto da mensagem
        iv_client = msg[0:16]
        mac_client = msg [16:48]
        novamensagem = msg[48:]

        ctp = encriptarcli (keyaes, iv_client, novamensagem)

        #imprimir mensagem
        #txt = msg.decode()
        print('%d : %r' % (self.id,ctp))
        #new_msg = txt.upper().encode()
        iv = os.urandom(16)

        ct = encriptarserver(keyaes, iv, ctp)
        # hmac da mensagem
        final= hmacserver(keymac,ct)
        msgfinal = iv + final + ct
        return msgfinal if len(msgfinal)>0 else None



@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.4', conn_port, loop=loop)
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
