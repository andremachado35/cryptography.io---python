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
from cryptography.hazmat.backends import default_backend\

#imports do Delfie
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
#outros imports
from sys import stdin



backend = default_backend()
conn_port = 8888
max_msg_size = 9999


file=open("key.txt","rb")
key=file.read()
derived_key_2=key[0:16]
key_mac=key[16:32]
file.close()

backend=default_backend()
salt=os.urandom(16)

def mensagemboasvinda(self):
    str = 'PHello'
    return str.encode()

class Client:
    """ Cl.upasse que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        " Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0


    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
            #primeiro p e g
        self.msg_cnt += 1
        if msg == b'':
            msg = mensagemboasvinda(self)
            return msg
        while len(msg)>0:
            if msg:
                if (msg[:1]==b'E'): break
                if (msg[:1]==b'P'):
                    global derived_key_2
                    G=int(msg[1:309].decode())
                    P=int(msg[309:617].decode())
                    public_key_server = int( msg[617:].decode())
                    #done
                    #criar private key do cliente
                    pn =  dh.DHParameterNumbers(P,G)
                    parameters = pn.parameters(default_backend())
                    private_key_2 = parameters.generate_private_key()
                    public_key_cliente = private_key_2.public_key().public_numbers().y
                    #peer_public_key_2 = parameters.generate_private_key().public_key()
                    #CALCULAR exchange
                    peerPublicNumbers2 = dh.DHPublicNumbers(public_key_server, pn)
                    peer_key2 = peerPublicNumbers2.public_key(default_backend())
                    shared_key_2 = private_key_2.exchange(peer_key2)
                    tmp = 'S'+str(public_key_cliente)
                    msg = tmp.encode()
                    derived_key_2 = HKDF(
                        algorithm=hashes.SHA512(),
                        length=24,
                        salt=None,
                        info=b'handshake data',
                        backend=default_backend()
                    ).derive(shared_key_2)
                    return msg

                elif (msg == b'1'):
                    print('Received (%d): %r' % (self.msg_cnt , msg))
                    print('Input message to send (empty to finish)')
                    new = input().encode()

                    iv_c = os.urandom(16)
                    cipher = Cipher(algorithms.AES(derived_key_2), modes.CTR(iv_c), backend=backend)
                    encryptor = cipher.encryptor()

                    ct = encryptor.update(new) + encryptor.finalize()
                    #HMAC
                    h=hmac.HMAC(key_mac,hashes.SHA256(),backend=default_backend())
                    h.update(ct)
                    mac_sig = h.finalize()
                    carater = b'C'
                    new_msg =carater+ iv_c+mac_sig+ct


                    return new_msg if len(new_msg)>0 else None
                    process()

                elif  (msg[:1] == b'2'):
                    iv_serv = msg[1:17]
                    mac_serv = msg[17:49]
                    texto = msg [49:]

                    cipher = Cipher(algorithms.AES(derived_key_2), modes.CTR(iv_serv), backend=backend)
                    decryptor = cipher.decryptor()

                    h=hmac.HMAC(key_mac,hashes.SHA256(),backend=default_backend())
                    h.update(texto)
                    mac_sig = h.finalize()

                    txt=decryptor.update(texto) + decryptor.finalize()
                    msg=txt.decode()

                    if(mac_sig==mac_serv):
                        print("Palavra-passe verificada com sucesso")
                        print('Mensagem nr.(%d): %r' % (self.msg_cnt , msg))
                        print('Input message to send (empty to finish)')
                        print(mac_sig)
                        new = input().encode()
                        iv_c = os.urandom(16)
                        cipher = Cipher(algorithms.AES(derived_key_2), modes.CTR(iv_c), backend=backend)
                        encryptor = cipher.encryptor()
                        ct = encryptor.update(new) + encryptor.finalize()
                        carater = b'C'
                        new_msg=carater+ iv_c+mac_sig+ct

                        return new_msg if len(new_msg)>0 else None

                    else:
                        print("mensagem recebida está errada")

@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('0.0.0.0',conn_port, loop=loop)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
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
