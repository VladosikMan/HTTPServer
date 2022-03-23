package server;


import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import nl.altindag.ssl.SSLFactory;


public class SettingsSSL {
    //����� ��� ��������� SSL

    private SSLFactory sslFactory;

    public SettingsSSL() {
        sslFactory = SSLFactory.builder()
                // ����� �������� ������������ ����������
                .withSwappableIdentityMaterial()
                .withSwappableTrustMaterial()


                // ����������� jdk � OS
                .withDefaultTrustMaterial()
                .withProtocols("TLSv1.3", "TLSv1.2")
                .withCiphers("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")

                //.withIdentityMaterial(privateKey, privateKeyPassword, certificateChain)
                //.withSessionTimeout(3600) // Amount of seconds until it will be invalidated
                //.withSessionCacheSize(1024) // Amount of bytes until it will be invalidated

                .build();
    }

    public void setConfigeSSL() {
        //�������� ��� ����������� ��� ssl ������������� �������


    }

    public SSLFactory geSslFactory() {
        return sslFactory;
    }
}
