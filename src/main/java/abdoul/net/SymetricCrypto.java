package abdoul.net;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class SymetricCrypto {
    public static void main(String[] args) throws Exception {
        CryptoUtils cryptoUtils = new CryptoUtils();
        String data = "Hi how are you";
        String key = "12345678901234561234567890123456";
        SecretKey secretKey1=cryptoUtils.keyGenerator();
        System.out.println("My Secrete keyGenerated is: "+ Arrays.toString(secretKey1.getEncoded()));
        System.out.println("My Secrete keyGenerated is: "+new String(secretKey1.getEncoded()));
        System.out.println(key.length());
        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(),0,(new String(secretKey1.getEncoded())).length() ,"AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedData = cipher.doFinal(data.getBytes());
        String encodedEncrypteData = Base64.getEncoder().encodeToString(encryptedData);
        System.out.println("EcodedEncryptedData: "+encodedEncrypteData);
    }
}
