package abdoul.net;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DecrypteAES {

    public static void main(String[] args) throws Exception {
        String data = "gXsTjB7u0DwqvAtPfhKTag==";
        String key = "12345678901234561234567890123456";
        System.out.println(key.length());
        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(),0,key.length() ,"AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] doFinal = cipher.doFinal(Base64.getDecoder().decode(data));
        System.out.println(new String(doFinal));
    }
}
