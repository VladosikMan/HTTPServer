package server;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Cryprography {
    public Cryprography() {

    }
    public PrivateKey getPrivateKeyFromPath(String path) throws IOException, URISyntaxException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(this.getFileFromResourceAsByteArray(path));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(spec);
        return  privKey;
    }

    public X509Certificate getCertificateFromPath(String path){
        X509Certificate cert = null;

        try (InputStream inStream = this.getFileFromResourceAsStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
        } catch (Exception e) {

        }

        return null;
    }
    private byte[] getFileFromResourceAsByteArray(String fileName) throws URISyntaxException, IOException {
        return Files.readAllBytes(Paths.get(this.getClass().getClassLoader().getResource(fileName).toURI()));
    }
    private File getFileFromResource(String fileName) throws URISyntaxException {

        ClassLoader classLoader = getClass().getClassLoader();
        URL resource = classLoader.getResource(fileName);
        if (resource == null) {
            throw new IllegalArgumentException("file not found! " + fileName);
        } else {
            return new File(resource.toURI());
        }

    }
    private InputStream getFileFromResourceAsStream(String fileName) {

        // The class loader that loaded the class
        ClassLoader classLoader = getClass().getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(fileName);

        // the stream holding the file content
        if (inputStream == null) {
            throw new IllegalArgumentException("file not found! " + fileName);
        } else {
            return inputStream;
        }

    }
}
