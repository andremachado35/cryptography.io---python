from OpenSSL import crypto
#torna o ficheiro servidor.p12 -> servidor.pem
def getCertificate(p):
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM,p.get_certificate())
    return cert
#verifica do ficheiro (servidor.pem+ca.pem)
def verify(cert,cacert,verifica):
        if verifica:
            print("certificado verificado")
#verificação do servidor.p12 + ca.cer
def verify_chain_of_trust(cert,rootcert):
    certificado = crypto.load_certificate(crypto.FILETYPE_PEM,cert)
    ca_certificado = crypto.load_certificate(crypto.FILETYPE_ASN1,rootcert)
    st = crypto.X509Store()
#concatenação do servidor.pem + ca.pem
    st.add_cert(certificado)
    st.add_cert(ca_certificado)
    st_ctx = crypto.X509StoreContext(st,certificado)
    result = st_ctx.verify_certificate()

    if result is None:
        return True
    else:
        return False

#abre o ficheiro servidor.p12
svrp = crypto.load_pkcs12(open("Servidor.p12",'rb').read(),"1234")
print(svrp.get_certificate())
svrcert = getCertificate(svrp)
cert = svrcert
#abre o ficheiro ca.cer e torna-o como root para verifcar
with open("CA.cer",'rb') as root_cert_file:
    rootcert = root_cert_file.read()
    verifica = verify_chain_of_trust(cert,rootcert)
cacert = rootcert
verify(cert,cacert,verifica)
