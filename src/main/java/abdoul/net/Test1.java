package abdoul.net;

import org.apache.commons.codec.DecoderException;

import java.util.Arrays;
import java.util.Base64;

public class Test1 {
    public static void main(String[] args) throws DecoderException {
        CryptoUtils cryptoUtils = new CryptoUtils();

        String document="Hello World";

        byte[] bytes = document.getBytes();
        String base64Encoded = cryptoUtils.base64Encode(bytes);
        System.out.println("Base64: " + base64Encoded);

        byte[] bytes2 = cryptoUtils.base64Decode(base64Encoded);
        String document2 = new String(bytes2);
        System.out.println("Document: " + document2);

        String hexEncode = cryptoUtils.hexEncode(document.getBytes());
        System.out.println("Hex: " + hexEncode);

        byte[] bytes3 = cryptoUtils.hexDecode(hexEncode);
        String document3 = new String(bytes3);
        System.out.println("decode to document: " + document3);


    }
}
