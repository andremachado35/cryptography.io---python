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
def getCertificado(clp12):
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM,clp12.get_certificate())
    print("certificado\n")
    print(cert)
    return cert
    #extrair a chave privada
def extractPrivate(clp12):
    kprivate = clp12.get_privatekey()
    pe = crypto.dump_privatekey(crypto.FILETYPE_PEM,kprivate)
    keypri = serialization.load_pem_private_key(pe,password=None,backend=default_backend())
    return keypri
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

def SignatureMessage(msg,keyprivatecli):
    signature = keyprivatecli.sign(
        msg,
        padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    return signature

def verifySignature(vsign,pub_svr,gyxx):
    pub_svr.verify(
        vsign,
        gyxx,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
     ),
     hashes.SHA256()
)
    try:
     pub_svr.verify(
         vsign,
         gyxx,
         padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
 )
    except InvalidSignature:
        print("Assinatura Inválida\n")
        #verificação das assinaturas
        #extrair a chave pública
def extractPublic(svrpem):
    p = x509.load_pem_x509_certificate(svrpem,default_backend())
    keypublicsvr = p.public_key()
    return keypublicsvr

    #obter certificado pem Cliente.p12 -> Cliente.pem

    #verificação
def verifica(svrpem):
    with open("ca.cert.pem",'rb') as root_cert_file:
        rootcert = root_cert_file.read()
    with open("ca-chain.cert.pem",'rb') as int_cert_file:
        intcert = int_cert_file.read()
    trusted_certs = (intcert,rootcert)
    verificado = verify_chain_of_trust(svrpem,trusted_certs)
    if verificado:
            print("Certificado verificado e válido\n")
    return verificado
    #verificação com Ca.pem + Cliente.pem
def verify_chain_of_trust(cert,trusted_certs):
    certificado = crypto.load_certificate(crypto.FILETYPE_PEM,cert)
    st = crypto.X509Store()
    for trusted_cert in trusted_certs:
        trust_certificado = crypto.load_certificate(crypto.FILETYPE_PEM,trusted_cert)
        st.add_cert(trust_certificado)
    st.add_cert(certificado)
    st_ct = crypto.X509StoreContext(st,certificado)
    out = st_ct.verify_certificate()
    if out is None:
        return True
    else:
        return False


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
                    global public_key_file_server_serial
                    P = 99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583
                    G = 44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675
                                        #ve qual é a chave publica DH server
                    public_key_server_dh = int( msg[1:].decode())
                                        #dh do cliente
                    pn =  dh.DHParameterNumbers(P,G)
                    parameters = pn.parameters(default_backend())
                                        #criar private key dh do cliente
                    private_key_cliente_dh = parameters.generate_private_key()
                                        #gerar public key dh do cliente
                    public_key_cliente_dh = private_key_cliente_dh.public_key().public_numbers().y
                                        #atraves da public key dh cria objeto para calcular chave Partilhada
                    peerPublicNumbers2 = dh.DHPublicNumbers(public_key_server_dh, pn)
                    peer_key2 = peerPublicNumbers2.public_key(default_backend())

                                        #Lê o ficheiro p12 para extrair a sua chave privada
                    filepriv = open("privateKeyCli.pem","rb")
                    keyprivateclii = filepriv.read()
                    filepriv.close()
                                        #fazer serializacao chave privada ficheiro do cliente
                    private_key_file_cliente_serial = serialization.load_pem_private_key(
                        keyprivateclii,
                        password=None,
                        backend=default_backend()
                    )
                                         #- Lê chave pública do ficheiro do servidor
                    filepub = open("publicKeySvr.pem","rb")
                    keypublicread = filepub.read()
                    filepub.close()
                                        #fazer serializacao chave publica ficheiro do SERVIDOR
                    public_key_file_server_serial = serialization.load_pem_public_key(
                        keypublicread,
                        backend=default_backend()
                    )

                    clp12 = crypto.load_pkcs12(open("client.p12",'rb').read(),"xpto")
                    print (clp12)
                    clpem = getCertificado(clp12)
                    keyprivatecli = extractPrivate(clp12)
                                        #concatenar chave publica dh server + chave publica dh cliente
                    gxgy= str (public_key_server_dh) + str(public_key_cliente_dh)
                    global gyxx

                    gyxx= gxgy.encode()
                                        #assinatura = gxgy + chave privada ficheiro cliente serial
                    signature = keyprivatecli.sign(
                    gyxx,
                    padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                    hashes.SHA256()
                    )
                    public_key_cliente_dh_2 = str(public_key_cliente_dh).encode()
                                        #envia assinatura + certificado + chave pública
                    tmp = b'S'+ signature+ public_key_cliente_dh_2+ clpem
                    shared_key_2 = private_key_cliente_dh.exchange(peer_key2)
                    derived_key_2 = HKDF(
                        algorithm=hashes.SHA512(),
                        length=24,
                        salt=None,
                        info=b'handshake data',
                        backend=default_backend()
                    ).derive(shared_key_2)
                    print (signature)
                    print (public_key_cliente_dh_2)
                    print (clpem)
                    return tmp
                                    #finito
                                        #reopen
                if (msg[:1] == b'm'):
                                    #- Recebe Assinatura
                    print ("entra aqui")
                    vsign = msg[1:257]
                    svrpem = msg[257:]
                    print("here\n")
                    print(svrpem)
                    print("svrpem\n")
                    verificacao = verifica(svrpem)
                    if verificacao:
                        pub_svr = extractPublic(svrpem)
                        verifySignature(vsign,pub_svr,gyxx)
                        print('é seguro falarmos')
                        balhelhe=b'4'
                        return balhelhe
                    else:
                        print (signature)
                        print (public_key_cliente_dh)
                        print (clpem)
                        msg = b'S' + signature + clpem

                if (msg[:1] == b'4'):

                    iv_recebido=msg[1:17] #chave de aes
                    mac_recebido=msg[17:49]
                    new_msg=msg[49:]

                    #imprime mensagem recebida
                    print('Received (%d): %r' % (1, msg))
                    print('Input message to send (empty to finish)')
                    new_msg_encode = input().encode()
                    iv_servido=os.urandom(16)
                    #encriptar
                    ct = encriptarcliente (keyaes, iv_servido, new_msg_encode)
                    #hmac
                    hmacfin = hmaccliente (keymac,ct)
                    #verificamac(self,msg,hmacfin,mac_recebido)
                    iv_cliente = os.urandom(16)
                    mensagem =b'C'+iv_servido + hmacfin + ct
                    return mensagem if len(mensagem)>0 else None
                else:

                #desencriptar

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
                            msgpv = iv_posve + hmacfin + ct
                            print(msgpv)
                            return msgpv if len(msgpv)>0 else None
                    else:
                            print('deu erro, nao e igual')


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
