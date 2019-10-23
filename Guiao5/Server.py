# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import os
import sys

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

#imports do Delfie
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#outros imports
from random import randint

masterpassword = get_random_bytes(16)
conn_cnt = 0
conn_port = 8888
max_msg_size = 9999
backend = default_backend()
file=open("key.txt","wb");
backend=default_backend()
salt=os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=256,
    salt=salt,
    iterations=100000,
    backend=backend
)

key=kdf.derive(b"mypassword")

derived_key=key[0:16]   #derived_key ChaCha
key_mac=key[16:32] #derived_key HMAC

file.write(key)
file.close()
#salt = get_random_bytes(64) # with 64 bytes
class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.fase_utilizacao=0

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        if(msg[:1]==b'P'):

            P = 99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583
            G = 44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675
            global pn
            global private_key
            global derived_key
            pn =  dh.DHParameterNumbers(P,G)
            parameters = pn.parameters(default_backend())
                        #chave privada do server
            #parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            private_key = parameters.generate_private_key()
            #gerar chave publica

            public_key = private_key.public_key()
            public_key_server= public_key.public_numbers().y
            res = 'P'+str(G)+str(P) + str(public_key_server)
            ress = res.encode()
            msg = ress
            return msg

        elif(msg[:1]==b'S'):
            public_key_cliente =int (msg[1:].decode())
            #CALCULAR exchange
            peerPublicNumbers = dh.DHPublicNumbers(public_key_cliente, pn)
            peer_key = peerPublicNumbers.public_key(default_backend())
            shared_key = private_key.exchange(peer_key)
            # Perform key derivation.
            derived_key = HKDF(
                 algorithm=hashes.SHA512(),
                 length=24,
                 salt=None,
                 info=b'handshake data',
                 backend=default_backend()
             ).derive(shared_key)
            msg2s = '1'
            msg2 = str(msg2s).encode()
            return msg2

        elif (msg[:1] == b'C'):
            iv_cl = msg[1:17]
            mac_cli=msg[17:49]
            texto=msg[49:]

            cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv_cl), backend=backend)
            decryptor = cipher.decryptor()
            txt=decryptor.update(texto)
            #print("txt")
            #print(txt)
            #txt=txt.decode()

            #h=hmac.HMAC(key,hashes.SHA256(),backend=default_backend())
            #h.update(texto)
            #h.copy().verify(mac_cli)
            print('%d : %r' % (self.id,txt))
            #if(h.copy().verify(mac_cli)):
            #    print("mensagem recebida correta")
            #    print('Recebi (%d): %r' % (self.msg_cnt , msg))
            #else:
            #    printf("mensagem recebida está errada")
            #    print('%d : %r' % (self.id,t))

            #new = txt.upper().encode()

            iv_s = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv_s), backend=backend)
            encryptor = cipher.encryptor()
            ct = encryptor.update(txt) + encryptor.finalize()
            ####################################
            #HMAC
            h=hmac.HMAC(key_mac,hashes.SHA256(),backend=default_backend())
            h.update(ct)
            mac_serv = h.finalize()
            carater = b'2'
            new_msg = carater + iv_s+mac_serv+ct
            ########################
            return new_msg if len(new_msg)>0 else None
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
    coro = asyncio.start_server(handle_echo, '0.0.0.0', conn_port, loop=loop)
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
