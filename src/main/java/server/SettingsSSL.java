package server;


import nl.altindag.ssl.SSLFactory;

import java.security.PrivateKey;
import java.security.cert.Certificate;


public class SettingsSSL {
    //����� ��� ��������� SSL

    private SSLFactory sslFactory;

    public SettingsSSL() {
    }

    public void setConfigeSSL() {

        //�������� ��� ����������� ��� ssl ������������� �������
        Cryprography cryprography = new Cryprography();
        cryprography.generatePair();
        PrivateKey privateKey = cryprography.getPrivateKey();
        Certificate certificate = cryprography.generateX509Certificate(cryprography.getKeyPair());

//        System.out.println(privateKey);
//
//        System.out.println("--------------------------");
//        System.out.println(certificate);

        sslFactory = SSLFactory.builder()

                // ����� �������� ������������ ����������
                .withSwappableIdentityMaterial()
                .withSwappableTrustMaterial()


                // ����������� jdk � OS
                .withDefaultTrustMaterial()
                .withProtocols("TLSv1.3", "TLSv1.2")
                .withCiphers("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")

                .withIdentityMaterial(privateKey, Constants.privateKeyPassword, certificate)
                //.withIdentityMaterial(privateKey, privateKeyPassword, certificateChain)
                //.withSessionTimeout(3600) // Amount of seconds until it will be invalidated
                //.withSessionCacheSize(1024) // Amount of bytes until it will be invalidated

                .build();


    }

    public SSLFactory geSslFactory() {
        return sslFactory;
    }
}
