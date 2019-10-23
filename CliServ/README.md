# 1819-G7 - Aplicação Cliente e Servidor final
Fase de inicialização: Cliente e Servidor retiram a chave privada respetiva dos certificados gerados, assinam e trocam certificados para assegurar que comunicam com quem pretendem (Cliente com Servidor e Servidor com Cliente).
O protocolo Diffie-Helmman é mantido pois este gera as chaves para cada sessão entre Cliente e Servidor permitindo assim um canal de comunicação mais robusto e seguro.
Após Cliente e Servidor assegurarem um canal de comunicação seguro é iniciado a troca a troca de mensagens entre Cliente e Servidor à qual os dados da comunicação estão seguros pois estes estão protegidos pela Cifra AES no modo CTR do guião4.
