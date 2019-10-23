# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
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

#Bibliotecas
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL import crypto
from cryptography import x509


masterpassword = get_random_bytes(16)
conn_cnt = 0
conn_port = 8888
max_msg_size = 9999
backend = default_backend()
f = open('achave.txt','wb')
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

    #extrai a chave publica
def extractPublic(clipem):
    p = x509.load_pem_x509_certificate(clipem,default_backend())
    publickeysvr = p.public_key()
    return publickeysvr
    #extrai a chave privada

def verifica(clipem):
    with open("CA.cer",'rb') as  root_cert_file:
        rootcert = root_cert_file.read()
        verificado = verify_chain_of_trust(clipem,rootcert)
    if verificado:
        print("Certificado verificado e válido\n")
    return verificado

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
def SignatureMessage(gxy,keyprivatesvr):
    signature = keyprivatesvr.sign(
        gxy,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verifySignature(vsign,publica,gxy):
    publica.verify(
        vsign,
        gxy,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
     ),
     hashes.SHA256()
)
    try:
        publica.verify(
             vsign,
             gxy,
             padding.PSS(
                 mgf=padding.MGF1(hashes.SHA256()),
                 salt_length=padding.PSS.MAX_LENGTH
                 ),
          hashes.SHA256()
         )
    except InvalidSignature:
        print("Assinatura Inválida\n")



def extractPrivate(svrp12):
    kprivate = svrp12.get_privatekey()

    pe = crypto.dump_privatekey(crypto.FILETYPE_PEM,kprivate)
    privatekeysvr = serialization.load_pem_private_key(pe,password=None,backend=default_backend())
    return privatekeysvr
    #obter certificado pem Servidor.p12 -> Servidor.pem
def getCertificado(svrp12):
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM,svrp12.get_certificate())
    print("cert\n")
    print(cert)
    return cert

#verificação com Ca.pem + Servidor.pem
def verify_chain_of_trust(cert,rootcert):
    certificado = crypto.load_certificate(crypto.FILETYPE_PEM,cert)
    ca_certificado = crypto.load_certificate(crypto.FILETYPE_ASN1,rootcert)
    st = crypto.X509Store()
    st.add_cert(certificado)
    st.add_cert(ca_certificado)
    st_ct = crypto.X509StoreContext(st,certificado)
    result = st_ct.verify_certificate()
    if result is None:
        return True
    else:
        return False

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
            global private_key_dh_server
            global public_key_server_dh
            global derived_key
            pn =  dh.DHParameterNumbers(P,G)
            parameters = pn.parameters(default_backend())
                        #chave privada do server
            private_key_dh_server = parameters.generate_private_key()
                        #gerar chave publica
            public_key = private_key_dh_server.public_key()
            public_key_server_dh= public_key.public_numbers().y
                        #envia chave publica dh do server
            res = 'P'+ str(public_key_server_dh)
            ress = res.encode()
            msg = ress
            return msg

        if(msg[:1]==b'S'):
                                #ler assinatura do cliente
            vsign = msg[1:257]
            public_key_cliente_dh = msg[257:565]
            clipem = msg[565:]
            print("here\n")
            print("clipem\n")
            print(vsign)
            print(public_key_cliente_dh)
            print(clipem)
            '''
            peerPublicNumbers = dh.DHPublicNumbers(public_key_cliente_dh, pn)
            peer_key = peerPublicNumbers.public_key(default_backend())
            public_key_server_dh_peer = private_key_dh_server.exchange(peer_key)
            '''

                                #verifica Certificado
            verificacao = verifica(clipem)
            if verificacao:
                publica = extractPublic(clipem)
                                #concatenar gxgy  = public key dh server + public_key_dh public_key_client

            gxgy = str(public_key_server_dh).encode()
            gxy = gxgy + public_key_cliente_dh
                                # verificar assinatura
            verifySignature(vsign, publica, gxy)
                                #extrair chave privada file do servidor
            svrp12 = crypto.load_pkcs12(open("Servidor.p12",'rb').read(),"1234")


            svrpem = getCertificado(svrp12)
            global cert
            cert = svrp12
            keyprivatesvr = extractPrivate(svrp12)

                                #4º - Assina gxgy com priv_servidor
            signature_Server = keyprivatesvr.sign(
            gxy,
            padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                    ),
            hashes.SHA256()
            )
            '''
            derived_key = HKDF(
                 algorithm=hashes.SHA512(),
                 length=24,
                 salt=None,
                 info=b'handshake data',
                 backend=default_backend()
             ).derive(shared_key)
             '''
                                #5º - Envia assinaturax
            msgcomsign = b'm' + signature_Server + svrpem
            return msgcomsign


        if (msg[:1] == b'4'):
            balhelhe =b'4'
            print('é seguro falarmos')
            return balhelhe

        if (msg[:1] == b'C'):

            self.msg_cnt += 1
            #dividir iv do hmac do texto da mensagem
            iv_client = msg[1:17]
            mac_client = msg [17:49]
            novamensagem = msg[49:]
            ctp = encriptarcli (keyaes, iv_client, novamensagem)
            print('%d : %r' % (self.id,ctp))
            iv = os.urandom(16)
            ct = encriptarserver(keyaes, iv, ctp)
            # hmac da mensagem
            final= hmacserver(keymac,ct)
            msgfinal =b'4'+ iv + final + ct
            return msgfinal if len(msgfinal)>0 else None


@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    CAf = open("CA.cer",'rb')
    CA = CAf.read()
    CAf.close()
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
