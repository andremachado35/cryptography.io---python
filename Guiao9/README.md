# 1819-G7 - Guião 9

Neste guia o pretendido era gerar os certificados para aplicação Cliente e Servidor. O grupo utilizou os certificados gerados do tutorial:https://jamielinux.com/docs/openssl-certificate-authority/index-full.html, as dificuldades sentidas foi maioritarmente alguns erros que os comandos davam, mas com alguma pesquisa foram superadas.
Após gerado os certificados, era pretendido a incorporação destes na aplicação Cliente e Servidor à qual foi preciso acrescentar o certificado intermediário gerado, para além dos certificados root, servidor e cliente, para a verificação do chain of trust dos certificados. Com o apoio da seguinte referência http://www.yothenberg.com/validate-x509-certificate-in-python/, o grupo conseguiu superar alguns erros encontrados ao testar a aplicação Cliente e Servidor com os certificados gerados.
Este guia foi realizado com sucesso tanto na geração dos certificados como na incorporação destes na aplicação.
