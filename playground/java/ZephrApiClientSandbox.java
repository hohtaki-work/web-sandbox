package playground.java;

import java.security.MessageDigest;
import java.util.HexFormat;

public class ZephrApiClientSandbox {
    public static final String algorithm = "SHA-256";

    public static String signRequest(String secretKey, String body, String path, String query, String method,
            String timestamp, String nonce) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(secretKey.getBytes());
        messageDigest.update(body.getBytes());
        messageDigest.update(path.getBytes());
        messageDigest.update(query.getBytes());
        messageDigest.update(method.getBytes());
        messageDigest.update(timestamp.getBytes());
        messageDigest.update(nonce.getBytes());

        byte[] digest = messageDigest.digest();
        HexFormat hex = HexFormat.of();
        String hash = hex.formatHex(digest);

        return hash;
    }

    public static void main(String[] args) throws Exception {
        String accessKey = args[0];
        String secretKey = args[1];
        String body = args[2];
        String path = args[3];
        String query = args[4];
        String method = args[5];
        String timestamp = args[6];
        String nonce = args[7];

        String requestHash = ZephrApiClientSandbox.signRequest(secretKey, body, path, query, method, timestamp, nonce);
        System.out.println(requestHash);
    }
}