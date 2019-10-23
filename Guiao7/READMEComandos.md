# 1819-G7
Comandos Usados:
#Extrair a informação para o ficheiro Cliente.pem e Servidor.pem
openssl pkcs12 -in Cliente.p12 -out Cliente.pem
openssl pkcs12 -in Cliente.p12 -clcerts -out Cliente.pem
openssl pkcs12 -in Servidor.p12 -out Servidor.pem
openssl pkcs12 -in Servidor.p12 -clcerts -out Servidor.pem
#Concatenação do CLiente e Servidor para um ficheiro novo trust -> Cliente  e trustSvr -> Servidor
cat Cliente.pem Ca.pem > trust.pem
cat Servidor.pem Ca.pem > trustSvr.pem
#Verificação dos ficheiros
openssl verify -CAfile trust.pem Ca.pem
openssl verify -CAfile trustSvr.pem Ca.pem
#Output:
Ca.pem: OK

