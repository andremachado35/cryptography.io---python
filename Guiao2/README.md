Neste guiao2 além do fernet utilizado no guiao1 foram introduzidos 3 novos conceitos : 
- hmac, para garantir autenticidade e integridade 
- chacha20 , cifra sequencial derivada do salsa20
- pbkdf, que visa construir uma chave aleatoria apartir de uma chave fraca.

 

no pbkdf utilizou-se: 
- comprimento : 64 
- nº iterações : 100000

onde 32 bytes foram para o chacha20 e 32 bytes para o hmac

