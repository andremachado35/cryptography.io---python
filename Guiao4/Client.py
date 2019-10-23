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


from sys import stdin


backend = default_backend()
conn_port = 8888
max_msg_size = 9999


#abrir ficheiro para escrever a key do aes e mac
f = open('achave.txt','rb')
aux = f.read()
keyx = aux
keyaes=keyx[0:16] #chave de aes
keymac=keyx[16:32] #chave de hmac
f.close()

def encriptarcliente (keyaes, iv_servido, new_msg_encode):

    cipher = Cipher(algorithms.AES(keyaes),modes.CTR(iv_servido), backend = backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(new_msg_encode)  + encryptor.finalize()
    return ct

def kdfsessionkey (saltdois,key_cliente):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=saltdois,
        iterations=100000,
        backend=backend
    )
    k = kdf.derive(b'key_cliente')
    return k


def hmaccliente (keymac,ct):
    hma = hmac.HMAC(keymac, hashes.SHA256(), backend=default_backend())
    hma.update(ct)
    hmacfin = hma.finalize()
    return hmacfin

def hmacclienteelse(keymac, new_msg):
    hma = hmac.HMAC(keymac, hashes.SHA256(), backend=default_backend())
    hma.update(new_msg)
    hmacfin = hma.finalize()
    return hmacfin

def encriptarelse(keyaes, iv_posve,new_msg_encode):
    cipher = Cipher(algorithms.AES(keyaes),modes.CTR(iv_posve), backend = backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(new_msg_encode)  + encryptor.finalize()
    return ct

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
        #FASE DE UTILIZACAO
        test=b''
        if (msg == b'1'):
            iv_recebido=msg[1:17] #chave de aes
            mac_recebido=msg[17:49]
            new_msg=msg[49:]
            print('Received (%d): %r' % (1, msg))
            print('Input message to send (empty to finish)')
            new_msg_encode = input().encode()
            #imprime mensagem recebida
            iv_servido=os.urandom(16)
            #encriptar
            ct = encriptarcliente (keyaes, iv_servido, new_msg_encode)
            #hmac
            hmacfin = hmaccliente (keymac,ct)
            iv_cliente = os.urandom(16)
            conf= '1'
            confirmarchat = str(conf).encode()
            mensagem = confirmarchat + iv_servido + hmacfin + ct
            return mensagem if len(mensagem)>0 else None

        if  (msg[:1] == b'2'):
            iv_recebido=msg[1:17] #chave de aes
            mac_recebido=msg[17:49]
            new_msg=msg[49:]
            cipher = Cipher(algorithms.AES(keyaes),modes.CTR(iv_recebido), backend = backend)
            decryptor = cipher.decryptor()
            #hmac
            hmacfin = hmacclienteelse (keymac, new_msg)
            txt= decryptor.update(new_msg) + decryptor.finalize()
            msg = txt.decode()
            #verificamac(self,msg,hmacfin,mac_recebido)

#Função para verificar o hmac
#def verificamac(self,msg,hmacfin,mac_recebido,msgpv=b''):
            if (hmacfin ==mac_recebido):
                    print('Received (%d): %r' % (self.msg_cnt , msg))
                    print('Input message to send (empty to finish)')
                    new_msg_encode= input().encode()
                    iv_posve = os.urandom(16)
                    ct=encriptarelse(keyaes, iv_posve,new_msg_encode)
                    confdois = '1'
                    confirmarchat = str(confdois).encode()
                    msgpv = confirmarchat + iv_posve + hmacfin + ct
                    return msgpv if len(msgpv)>0 else None
            else:
                    print('deu erro, nao e igual')

        if msg is test:
            if(len(sys.argv) <1):
                print("nao inseriu todos parametros")
            else:
                print('MANDOU STRING VAZIA')
                msg = ' '
                msgbyte = msg.encode()
                return msgbyte
        else:
            #if(sessionkey == msg):
                print('ABRI KEYSTORE1')
                file = open(sys.argv[1],"rb")
                contents = file.read()
                saltum = contents[0:16]
                key_cliente = contents [16:32]
                id_cli = contents[32:]
                file.close()
                saltdois = os.urandom(16) #random 16 bits
                sessionkey = kdfsessionkey(saltdois,key_cliente)
                print(sessionkey)
                print ('CRIOU SESSIONKEY')
                tramasalt2 = saltum + saltdois + id_cli
                x=bytearray(tramasalt2)
                return tramasalt2

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
