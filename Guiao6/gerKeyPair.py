#Bibliotecas
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

keysvr = b'passwordsvr'
keycli = b'passwordcli'

message = b'informacao extramamente delicada'

#Gerar chave privada file do Servidor
keyprivatesvr = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
 )
#Gerar chave privada file do cliente
keyprivatecli = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
  )

#Gerar chaves públicas Servidor
keypublicsvr = keyprivatesvr.public_key()

#gerar chave privada cliente
keypubliccli = keyprivatecli.public_key()

#3
#SignatureMessage() Server
message=b'mensagem de teste'
signature_Server = keyprivatesvr.sign(message,
padding.PSS(
    mgf = padding.MGF1(hashes.SHA256()),
    salt_length = padding.PSS.MAX_LENGTH
),
hashes.SHA256()
)
#SignatureMessage() cliente

signature_client = keyprivatecli.sign(message,

padding.PSS(
    mgf = padding.MGF1(hashes.SHA256()),
    salt_length = padding.PSS.MAX_LENGTH
),
hashes.SHA256()
)

#verificar assinatura Server
keypublicsvr.verify(
    signature_Server,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
 ),
 hashes.SHA256()
)
try:
 keypublicsvr.verify(
     signature_Server,
     message,
     padding.PSS(
         mgf=padding.MGF1(hashes.SHA256()),
         salt_length=padding.PSS.MAX_LENGTH
         ),
  hashes.SHA256()
 )
except InvalidSignature:
    print("Assinatura Inválida\n")

#verificar assinatura cliente
keypubliccli.verify(
    signature_client,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
 ),
 hashes.SHA256()
)
try:
 keypubliccli.verify(
     signature_client,
     message,
     padding.PSS(
         mgf=padding.MGF1(hashes.SHA256()),
         salt_length=padding.PSS.MAX_LENGTH
         ),
  hashes.SHA256()
 )
except InvalidSignature:
    print("Assinatura Inválida\n")

#Escrever privateKeySvr
privatepemsvr = keyprivatesvr.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = serialization.NoEncryption()
)
fpsvr = open("privateKeySvr.pem","wb")
fpsvr.write(privatepemsvr)
fpsvr.close()

#escrever privateKeyCli
privatepemcli = keyprivatecli.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = serialization.NoEncryption()
)

fpcli = open("privateKeyCli.pem","wb")
fpcli.write(privatepemcli)
fpcli.close()


publicpemsvr = keypublicsvr.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)
fps = open("publicKeySvr.pem","wb")
fps.write(publicpemsvr)
fps.close()


publicpemcli = keypubliccli.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)
fpc = open("publicKeyCli.pem","wb")
fpc.write(publicpemcli)
fps.close()


print("%r" %keyprivatesvr)
print("%r" %keyprivatecli)

print("%r" %keypublicsvr)
print("%r" %keypubliccli)
