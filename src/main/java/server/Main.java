package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class Main {
    public static void main(String[] args) throws Exception {
        // http://localhost:18443/
        ServerHTTPD serverHTTPD = new ServerHTTPD(8443);
        serverHTTPD.startServer();

    }
}
