/**
 * 10.3 evening
 * https://github.com/henrychen222/JavaEE-Project/blob/master/jsp%2Bservlet%2Bmysql%2BMD5%E5%A4%9A%E5%BC%8F%E8%81%94%E8%BF%90/lianyun/src/com/util/MD5.java
 */
package com.example.security.encryptionDecryption;

import sun.misc.BASE64Encoder;

import java.security.MessageDigest;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class MD5 {

    /**
     * @param args
     * @category MD5
     */
    MessageDigest m;
    BASE64Encoder b;
    String n;

    public String encrypt(String s) {
        try {
            s = s.trim();
            m = MessageDigest.getInstance("MD5");
            b = new BASE64Encoder();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            n = b.encode(m.digest(s.getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return n;
    }

    public static void main(String[] args) {
        String cipher = new MD5().encrypt("123");
        System.out.println(cipher);

        //some other example
        System.out.println(new MD5().encrypt("weichen"));
    }
}
