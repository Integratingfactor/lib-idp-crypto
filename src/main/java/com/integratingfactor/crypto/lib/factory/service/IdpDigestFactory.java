package com.integratingfactor.crypto.lib.factory.service;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.util.SerializationUtils;

import com.integratingfactor.crypto.lib.factory.exceptions.IdpDigestException;

/**
 * factory methods to compute digest for creating fingerprint when using
 * sensitive data as key in DB
 * 
 * @author gnulib
 *
 */
public class IdpDigestFactory {
    private static ThreadLocal<MessageDigest> digest = new ThreadLocal<MessageDigest>();

    public static final String DIGEST_ALGO = "SHA-1";

    private static MessageDigest myDigest() throws NoSuchAlgorithmException {
        MessageDigest digest = IdpDigestFactory.digest.get();

        if (digest == null) {
            digest = MessageDigest.getInstance(DIGEST_ALGO);
            IdpDigestFactory.digest.set(digest);
        }
        return digest;
    }

    public static <T extends Serializable> String getFingerPrint(T data) {
        try {
            byte[] hash = myDigest().digest(SerializationUtils.serialize(data));
            return new String(hash, "UTF-8");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpDigestException("failed to create digest " + e.getMessage());
        }
    }
}
