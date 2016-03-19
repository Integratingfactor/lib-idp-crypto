package com.integratingfactor.crypto.lib.factory.service;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.util.Base64Utils;
import org.springframework.util.SerializationUtils;

import com.integratingfactor.crypto.lib.factory.exceptions.IdpCryptoInitializationException;
import com.integratingfactor.crypto.lib.factory.exceptions.IdpDecryptionException;
import com.integratingfactor.crypto.lib.factory.exceptions.IdpEncryptionException;
import com.integratingfactor.crypto.lib.factory.model.IdpDecrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
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
    IdpSecretKeySpec spec;

    // protect constructor for any extended implementations
    protected IdpCryptoFactory() {

    }

    public static IdpCryptoFactory getInstance() {
        return new IdpCryptoFactory();
    }

    public <T extends Serializable> IdpEncrypted encrypt(T data) {
        // initialize cipher with key spec in encryption mode
        try {
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(Base64Utils.decodeFromString(spec.getKey()), spec.getKeyAlgorithm()));
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid secret key " + spec.getKey());
        }
        IdpEncrypted encrypted = new IdpEncrypted();
        encrypted.setIv(cipher.getIV());
        encrypted.setKeyVersion(spec.getVersion());
        try {
            encrypted.setCipherText(cipher.doFinal(SerializationUtils.serialize(data)));
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpEncryptionException("incorrect block size " + e.getMessage());
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpEncryptionException("incorrect padding " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpEncryptionException("encryption failed " + e.getMessage());
        }
        return encrypted;
    }

    public void init(IdpSecretKeySpec spec){
        this.spec = spec;
        // create a new instance for cipher based on spec's encryption algorithm
        try {
            cipher = Cipher.getInstance(spec.getEncryptionAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            throw new IdpCryptoInitializationException(
                    "Unsupport encryption algorithm " + spec.getEncryptionAlgorithm());
        }
    }

    @SuppressWarnings("unchecked")
    public <T extends Serializable> IdpDecrypted<T> decrypt(IdpEncrypted encrypted) {
        // initialize cipher with key spec and IV in decryption mode
        try {
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(Base64Utils.decodeFromString(spec.getKey()), spec.getKeyAlgorithm()),
                    new IvParameterSpec(encrypted.getIv()));
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid secret key " + spec.getKey());
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid key algorithm " + spec.getKeyAlgorithm());
        }
        IdpDecrypted<T> decrypted = new IdpDecrypted<T>();
        decrypted.setKeyVersion(encrypted.getKeyVersion());

        try {
            decrypted.setData((T) SerializationUtils.deserialize(cipher.doFinal(encrypted.getCipherText())));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new IdpDecryptionException("incorrect block size " + e.getMessage());
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new IdpDecryptionException("incorrect padding " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpDecryptionException("decryption failed " + e.getMessage());
        }
        return decrypted;
    }

}
