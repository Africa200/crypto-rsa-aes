package abdoul.net;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class TestRSA {

    public static void main(String[] args) throws Exception {
        CryptoUtils cryptoUtils = new CryptoUtils();
       /* KeyPair pair = cryptoUtils.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey =pair.getPublic();
        System.out.println("Private key:"+ Arrays.toString(privateKey.getEncoded()));
        System.out.println("private key: "+ Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public key:"+ Arrays.toString(publicKey.getEncoded()));
        System.out.println("public Key:"+ Base64.getEncoder().encodeToString(publicKey.getEncoded()));
*/
//        byte[] bytes = cryptoUtils.rsaEncrypt("Hi".getBytes(), publicKey);

//        System.out.println("Encrypted: "+ Base64.getEncoder().encodeToString(bytes));

        String publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLipRjKIVN+L3opMdysvZ12LT+uq5MmkNiif2c57SPT+DMVfjdeKDoa5E0bj/lRbHccv61eEiSk7VWe1rx2tWhwNkYGScuz4U8nk5YcyOmFI3KhKHCrH/5e8iRhIi7pHzo1HhqoeHuIbPtp/xJrJWceUd0IcQSxOYnKv41KqMWcQIDAQAB";
        String privateKeyStr = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIuKlGMohU34veikx3Ky9nXYtP66rkyaQ2KJ/ZzntI9P4MxV+N14oOhrkTRuP+VFsdxy/rV4SJKTtVZ7WvHa1aHA2RgZJy7PhTyeTlhzI6YUjcqEocKsf/l7yJGEiLukfOjUeGqh4e4hs+2n/EmslZx5R3QhxBLE5icq/jUqoxZxAgMBAAECgYABUAZtQdtYjf43hv0UANq1MrqhU3wSMj78X7tFq4wAL2jlDZFG5qYpCLtmKVWhlTSf4LckZoGhQYr9wz29Y2wQKVi6BVWMr9i4bmogzGLEC0Oq8hOiWVOpS2xkKfAYFQz3R0IZXKSP3Ex5L6G4dcgNZpMGizLpuNyJrbgsIRmxmQJBAPcb6+knHv8KjxaAXPeIjVewv2TvE/9gclOJswfImmsMpLZNSssbuef/dEkp8fGZ9YfOi4FTH2MakADyR6/TbikCQQCQj97UZRY4r8yhLwjb46wk3zLd7bOVC0ERJFlyAJSw1pCUJ4YkhcY8/gNpmFLEZNs5bTt2N2g6KiEnTjGoG18JAkEA7QEJtliAQStWa8V35S5CKk3qdBtd+bz+SiMy5A9CE9RPkk31o3KXTu1TEe06EXiR5sxyPvqDiyDp5w55NSk7aQJAbrR+pJC1L7wRLO5kDmCQF7yFq8a4286+iW4YwWEIfVQTbCHIbHe1lEfCPT9VQukpqRSpkKJlwwU4Vm1fQamUYQJAKWgmk8uAPbl/0Ke/JOeLGibDW7nex2Wnl5EJbMQiTmMs6hog+rKt6eNMMONhgZSo/i9v8zB1/kJ/w3zkkb7n6w==";

        PublicKey publicKey1 = cryptoUtils.getPublicKey(publicKeyStr);
        PrivateKey privateKey1 = cryptoUtils.getPrivateKey(privateKeyStr);

        byte[] bytes1 = cryptoUtils.rsaEncrypt("Hello".getBytes(), publicKey1);
        byte[] bytes2 = cryptoUtils.rsaDecrypt(bytes1, privateKey1);

        System.out.println("My message:   "+new String(bytes2));
    }
}
