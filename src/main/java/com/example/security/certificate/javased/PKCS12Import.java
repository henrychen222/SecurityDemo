/**
 * 10.3 evening
 * http://www.javased.com/index.php?api=java.security.cert.Certificate  (example 2)
 * http://www.javased.com/index.php?source_dir=jetty-project/jetty-pkcs12/src/main/java/org/mortbay/jetty/server/ssl/PKCS12Import.java
 *
 * Certificate
 * X509Certificate
 */
package com.example.security.certificate.javased;

import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class PKCS12Import {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println(
                    "usage: java PKCS12Import {pkcs12file} [newjksfile]");
            System.exit(1);
        }

        File fileIn = new File(args[0]);
        File fileOut;
        if (args.length > 1) {
            fileOut = new File(args[1]);
        } else {
            fileOut = new File("newstore.jks");
        }

        if (!fileIn.canRead()) {
            System.err.println(
                    "Unable to access input keystore: " + fileIn.getPath());
            System.exit(2);
        }

        if (fileOut.exists() && !fileOut.canWrite()) {
            System.err.println(
                    "Output file is not writable: " + fileOut.getPath());
            System.exit(2);
        }

        KeyStore kspkcs12 = KeyStore.getInstance("pkcs12");
        KeyStore ksjks = KeyStore.getInstance("jks");

        System.out.print("Enter input keystore passphrase: ");
        char[] inphrase = readPassphrase();
        System.out.print("Enter output keystore passphrase: ");
        char[] outphrase = readPassphrase();

        kspkcs12.load(new FileInputStream(fileIn), inphrase);

        ksjks.load((fileOut.exists()) ? new FileInputStream(fileOut) : null, outphrase);

        Enumeration eAliases = kspkcs12.aliases();
        int n = 0;
        while (eAliases.hasMoreElements()) {
            String strAlias = (String) eAliases.nextElement();
            System.err.println("Alias " + n++ + ": " + strAlias);

            if (kspkcs12.isKeyEntry(strAlias)) {
                System.err.println("Adding key for alias " + strAlias);
                Key key = kspkcs12.getKey(strAlias, inphrase);

                Certificate[] chain = kspkcs12.getCertificateChain(strAlias);

                ksjks.setKeyEntry(strAlias, key, outphrase, chain);
            }
        }

        OutputStream out = new FileOutputStream(fileOut);
        ksjks.store(out, outphrase);
        out.close();
    }

    static void dumpChain(Certificate[] chain) {
        for (int i = 0; i < chain.length; i++) {
            Certificate cert = chain[i];
            if (cert instanceof X509Certificate) {
                X509Certificate x509 = (X509Certificate) chain[i];
                System.err.println("subject: " + x509.getSubjectDN());
                System.err.println("issuer: " + x509.getIssuerDN());
            }
        }
    }

    static char[] readPassphrase() throws IOException {
        InputStreamReader in = new InputStreamReader(System.in);

        char[] cbuf = new char[256];
        int i = 0;

        readchars:
        while (i < cbuf.length) {
            char c = (char) in.read();
            switch (c) {
                case '\r':
                    break readchars;
                case '\n':
                    break readchars;
                default:
                    cbuf[i++] = c;
            }
        }

        char[] phrase = new char[i];
        System.arraycopy(cbuf, 0, phrase, 0, i);
        return phrase;
    }
}
