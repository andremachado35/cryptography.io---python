Neste guiao2 além do fernet utilizado no guiao1 foram introduzidos 3 novos conceitos : 
- hmac, para garantir autenticidade e integridade 
- chacha20 , cifra sequencial derivada do salsa20
- pbkdf, que visa construir uma chave aleatoria apartir de uma chave fraca.

Como parte deste conceitos teoricos ainda não tinham sido abordados nas aulas teoricas, foi um bocado confuso compreender tudo. 
Mas dividindo o problema em problemas menores o grupo conseguiu solucionar com sucesso. 

no pbkdf utilizou-se: 
- comprimento : 64 
- nº iterações : 100000

onde 32 bytes foram para o chacha20 e 32 bytes para o hmac

O grupo neste guiao apenas não gostou muito da ferramenta jupyter apesar de ter conseguido utiliza-la facilmente
