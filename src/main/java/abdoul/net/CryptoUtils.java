package abdoul.net;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {
    // Encode to Base64
    public  String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    //Decode from Base64
    public  byte[] base64Decode(String base64EncodedData) {
        return Base64.getDecoder().decode(base64EncodedData);
    }

    //Encode to Base64URL
    public  String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

    //Decode from Base64URL
    public  byte[] base64UrlDecode(String base64UrlEncodedData) {
        return Base64.getUrlDecoder().decode(base64UrlEncodedData);
    }

    //Encode to Hexadecimal
    public  String hexEncode(byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }

    //decode from Hexadecimal
    public  byte[] hexDecode(String hexEncodedData) throws DecoderException {
        return Hex.decodeHex(hexEncodedData);
    }

    //Encrypte with AES
    public  byte[] aesEncrypt(byte[] bytes, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(),0,key.length() ,"AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(bytes);
    }

    //Decrypte with AES
    public  byte[] aesDecrypt(byte[] bytes, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(),0,key.length() ,"AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(bytes);
    }

    //KeyGenerator
    public SecretKey keyGenerator() throws Exception {
       KeyGenerator generator = KeyGenerator.getInstance("AES");
       generator.init(256);
       return generator.generateKey();
    }

    //Genearte PairKey
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
        pairGenerator.initialize(1024);
        KeyPair pair = pairGenerator.generateKeyPair();
        return pair;
    }
    //Encrypte with RSA
    public  byte[] rsaEncrypt(byte[] bytes, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(bytes);
    }

    //Decrypte with RSA
    public  byte[] rsaDecrypt(byte[] bytes, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(bytes);
    }

    //Public Key with String Base64
    public PublicKey getPublicKey(String base64EncodedPublicKey) throws Exception {
        byte[] bytes = base64Decode(base64EncodedPublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    //Private Key With String Base64
    public PrivateKey getPrivateKey(String base64EncodedPrivateKey) throws Exception {
        byte[] bytes = base64Decode(base64EncodedPrivateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    //Public Key from Certificates
    public PublicKey getPublicKeyFromCertificate(String fileName) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;

    }

    //Private Key With JKS file
    public PrivateKey getPrivateKeyFromJKS(String fileName, String alias, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(fileName), password.toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        return privateKey;
    }

    // Signe document with HMAC
    public  String hmacSign(byte[] bytes, SecretKey secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        byte[] doFinal = mac.doFinal(bytes);
        return  Base64.getEncoder().encodeToString(doFinal);

    }

    //Hmac verification signature
    public boolean hmacVerify(byte[] bytes, String signature, SecretKey secretKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        byte[] doFinal = mac.doFinal(bytes);
        return  Base64.getEncoder().encodeToString(doFinal).equals(signature);
    }

    //signe document with RSA
    public String rsaSign(byte[] bytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(bytes);
        byte[] sign = signature.sign();
        return  Base64.getEncoder().encodeToString(sign);
    }

    //Verify signature with RSA
    public boolean rsaVerify(byte[] bytes, String signature, PublicKey publicKey) throws Exception {
        Signature signature1 = Signature.getInstance("SHA256withRSA");
        signature1.initVerify(publicKey);
        signature1.update(bytes);
        return signature1.verify(Base64.getDecoder().decode(signature));
    }
}
