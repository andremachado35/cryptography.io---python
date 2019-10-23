# 1819-G7 - Guião 8
Neste guião era pretendido o refinamento do protocolo Station to Station do guião 6, fazendo uso dos certificados x509. Com o uso e apoio da biblioteca https://pyopenssl.org/en/stable/api/crypto.html, o grupo entendeu como proceder à leitura das chaves dos certificados pois foi o desafio encontrado pelo grupo na realização do guião.
Como o formato dos certificados estavam em p12 e era pretendido a leitura das chaves não se podia efetuar a leitura das chaves como foi realizado no guião 6, então com o apoio encontrado na biblioteca indica acima, o grupo encontrou os parâmetros que permitem a esta leitura das chaves dos certificados.
Este guia foi realizado com sucesso pois assegura o protocolo Station to Station pretendido fazendo uso dos certificados e assegura o correto uso da chave pública na verificação da assinatura.


