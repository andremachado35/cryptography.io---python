A pasta /1tutorial contém os certificados realizando o tutorial de : 
https://pki-tutorial.readthedocs.io/en/latest/expert/

a pasta /ca/ contém os certificados recorrendo ao tutorial: 
https://jamielinux.com/docs/openssl-certificate-authority/index-full.html

Este segundo foi o que realmente se utilizou no guia. 

No primeiro após fazer o git clone lá pedido foi realizado o ponto 1 para realizar o root, o ponto dois para realizar o server e cliente.
O server foi realizado na pasta /network-ca/ e o client em /client/. Estes recorrem a diferentes ficheiros de configucao localizados em /etc/
root-ca.conf, server.conf e cliente.conf. 
Por último apesar de não serem convertidos para .p12, criou-se 2 clientes : 
- client1
- client2 

Utilizou-se para tal o ponto 3 com os ficheiros de configuração : 
-client1.conf
-client2.conf
que foram realizados apartir do network-ca.conf

O segundo tutorial foi o que realmente foi utilizado. 
Implementou-se o root, e um intermediate.
Utilizou-se assim por fim os comandos openssl pkcs12 que foram obtidos no 1º tutorial para converterr para p12
" openssl pkcs12- export -out -server.p12 -inket servidor.key.pem -in servidor.cert.pem .certfile intermediate.cert.pem"
e ainda " openssl pkcs12 -export -out client.p12 -inkey cliente.key.pem - in cliente.cert.pem -certfile intermediate.cer.pem
