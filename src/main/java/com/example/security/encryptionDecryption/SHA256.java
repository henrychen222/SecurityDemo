/**
 * 10.3 evening
 * https://www.baeldung.com/sha-256-hashing-java
 */
package com.example.security.encryptionDecryption;

import com.google.common.hash.Hashing;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256 {

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String originalString = "weichen";

        //SHA-256
        /** 2. MessageDigest Class in Java */
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = digest.digest(
                originalString.getBytes(StandardCharsets.UTF_8));
        System.out.println(encodedHash);

        /** 3. Guava Library */
        String encodedHash_Guava = Hashing.sha256()
                .hashString(originalString, StandardCharsets.UTF_8)
                .toString();
        System.out.println(encodedHash_Guava);

        /** 4. Apache Commons Codecs */
        String encodedHash_ApacheCommonsCodecs = DigestUtils.sha256Hex(originalString);
        System.out.println(encodedHash_ApacheCommonsCodecs);

        /** 5. Bouncy Castle Library */
        byte[] hash = digest.digest(
                originalString.getBytes(StandardCharsets.UTF_8));
        String encodedHash_BouncyCastleLibrary = new String(Hex.encode(hash));
        System.out.println(encodedHash_BouncyCastleLibrary);

    }

}
