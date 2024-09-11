package abdoul.net;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class TestRSAJKS {

    public static void main(String[] args) throws Exception {
        CryptoUtils cryptoUtils = new CryptoUtils();
        PrivateKey privateKeyFromJKS = cryptoUtils.getPrivateKeyFromJKS("my-release-key.jks", "Abdoulfatah", "123456");

        PublicKey publicKeyFromCERT = cryptoUtils.getPublicKeyFromCertificate("publicKey.cert");

        System.out.println("My Public Key : "+Base64.getEncoder().encodeToString(publicKeyFromCERT.getEncoded()));
        System.out.println("My Private Key : "+Base64.getEncoder().encodeToString(privateKeyFromJKS.getEncoded()));

    }
}
