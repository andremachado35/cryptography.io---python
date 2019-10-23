from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
t = open('mensagemsecreta.txt','r')#msg a encriptar
content = t.read()
a = bytes(content)
token = f.encrypt(a)#msg encriptada
t.close()
k = open('save.txt','w')#ficheiro para guardar a chave
k.write(key)
k.close()
fe = open('mensagemsegura.txt','w')#ficheiro encriptado
fe.write(token)
fe.close()
fd = open('teste.txt','w')#teste para ver se desencripta o ficheiro
aux = f.decrypt(token)
fd.write(aux)
fd.close()
