package abdoul.net;

import javax.crypto.SecretKey;

public class TestSignature {

    public static void main(String[] args) throws Exception {
        CryptoUtils cryptoUtils = new CryptoUtils();
        SecretKey secretKey = cryptoUtils.keyGenerator();
        String signature = cryptoUtils.hmacSign("Hello World".getBytes(), secretKey);
        System.out.println("Signature: " + signature);

        //Verfication
        boolean verification = cryptoUtils.hmacVerify("Hello World.".getBytes(), signature, secretKey);
        System.out.println("Verification: " + verification);
    }
}
