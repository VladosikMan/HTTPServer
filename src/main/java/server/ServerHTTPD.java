package server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

public class ServerHTTPD extends NanoHTTPD {

    //Наследуемый класс для работы с библиотекой NanoHTTPD

    public ServerHTTPD(int port) {

        //необходимо выполнить настройки ssl соединения
        super(port);
//        Cryprography cryprography =  new Cryprography();
//
//
//        PrivateKey privateKey = null;
//        try {
//            privateKey = cryprography.getPrivateKeyFromPath("keys/private_key.der");
//        } catch (URISyntaxException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//        X509Certificate certificate = cryprography.getCertificateFromPath("keys/public_key.der");
//
//        System.out.println(privateKey);
//        System.out.println(certificate);


        //start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);


    }

    public void startServer() throws Exception {
        SettingsSSL settingsSSL = new SettingsSSL();
        settingsSSL.setConfigeSSL();

        this.makeSecure(settingsSSL.geSslFactory().getSslServerSocketFactory(), null);
        try {
            this.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
        while (this.isAlive()) {
            try {
                Thread.sleep(100L);
            } catch (Throwable e) {
            }
        }
    }


    //основной метод который нужно переопределить для работы сервера
    @Override
    public Response serve(IHTTPSession session) {
        System.out.println("Yeee");
        return newFixedLengthResponse(Response.Status.OK, MIME_PLAINTEXT,
                "The requested resource does not exist");
    }

}