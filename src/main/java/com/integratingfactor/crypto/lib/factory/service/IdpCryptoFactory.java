package com.integratingfactor.crypto.lib.factory.service;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.util.Base64Utils;
import org.springframework.util.SerializationUtils;

import com.integratingfactor.crypto.lib.factory.exceptions.IdpCryptoInitializationException;
import com.integratingfactor.crypto.lib.factory.exceptions.IdpDecryptionException;
import com.integratingfactor.crypto.lib.factory.exceptions.IdpEncryptionException;
import com.integratingfactor.crypto.lib.factory.model.IdpDecrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
import com.integratingfactor.crypto.lib.factory.specs.IdpPbeKeySpec;
import com.integratingfactor.crypto.lib.factory.specs.IdpSecretKeySpec;

/**
 * factory class to encrypt plain-text into cipher-text with embedded IV and Key
 * version information in cipher-text
 * 
 * @author gnulib
 *
 */
public class IdpCryptoFactory {

    Cipher cipher;
    Key key;
    Integer version;

    private static final String PbeKeyAlgo = "PBKDF2WithHmacSHA1";

    // protect constructor for any extended implementations
    protected IdpCryptoFactory() {

    }

    public Key getKey() {
        return key;
    }

    public static IdpCryptoFactory getInstance() {
        return new IdpCryptoFactory();
    }

    public <T extends Serializable> IdpEncrypted encrypt(T data) {
        // initialize cipher with key spec in encryption mode
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid secret key " + key);
        }
        IdpEncrypted encrypted = new IdpEncrypted();
        encrypted.setIv(cipher.getIV());
        encrypted.setKeyVersion(version);
        try {
            encrypted.setCipherText(cipher.doFinal(SerializationUtils.serialize(data)));
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpEncryptionException("encryption failed " + e.getMessage());
        }
        return encrypted;
    }

    public void init(IdpSecretKeySpec spec) {
        // create a new instance for cipher and encryption key based on
        // definition
        try {
            this.cipher = Cipher.getInstance(spec.getEncryptionAlgorithm());
            this.key = new SecretKeySpec(Base64Utils.decodeFromString(spec.getKey()), spec.getKeyAlgorithm());
            this.version = spec.getVersion();
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpCryptoInitializationException("failed to initialize " + e.getMessage());
        }
    }

    public void init(IdpPbeKeySpec spec, char[] passPhrase) {
        // create a new instance for cipher based on definition and pass phrase
        try {
            this.cipher = Cipher.getInstance(spec.getEncryptionAlgorithm());
            this.key = new SecretKeySpec(SecretKeyFactory.getInstance(PbeKeyAlgo)
                    .generateSecret(
                            new PBEKeySpec(passPhrase, spec.getSalt(), spec.getDerivationCount(), spec.getKeySize()))
                    .getEncoded(), spec.getKeyAlgorithm());
            this.version = spec.getVersion();
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpCryptoInitializationException("failed to initialize " + e.getMessage());
        }

    }

    @SuppressWarnings("unchecked")
    public <T extends Serializable> IdpDecrypted<T> decrypt(IdpEncrypted encrypted) {
        // initialize cipher with key spec and IV in decryption mode
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypted.getIv()));
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid secret key " + key);
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid key algorithm " + e.getMessage());
        }
        IdpDecrypted<T> decrypted = new IdpDecrypted<T>();
        decrypted.setKeyVersion(encrypted.getKeyVersion());

        try {
            decrypted.setData((T) SerializationUtils.deserialize(cipher.doFinal(encrypted.getCipherText())));
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpDecryptionException("decryption failed " + e.getMessage());
        }
        return decrypted;
    }
}
