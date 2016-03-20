package com.integratingfactor.crypto.lib.factory.service;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;

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
import com.integratingfactor.crypto.lib.factory.model.IdpWrappedKeySpec;
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

    public <T extends Serializable> IdpEncrypted encryptBlocks(T data) {
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
            if (cipher.getBlockSize() > 0) {
                // need to encrypt block size bytes at a time
                byte[] txt = SerializationUtils.serialize(data);
                int blockSize = cipher.getBlockSize();
                int currTxt = 0;
                int currTxtSe = 0;
                // create a cipher text buffer based on estimated number of
                // blocks multiplied by estimated output size for each block
                // encryption
                byte[] txtSe = new byte[(cipher.getOutputSize(blockSize) * (1 + (txt.length / blockSize)))];
                // walk through intermediate blocks, when plain text is longer
                // than block size
                for (; currTxt < txt.length - blockSize; currTxt += blockSize) {
                    // encrypt intermediate block and copy into cipher text
                    // buffer
                    currTxtSe = copyBytes(cipher.update(txt, currTxt, blockSize), txtSe, currTxtSe);
                }
                // encrypt remaining bytes (after all intermediate blocks have
                // been encrypted) and copy into cipher text buffer
                currTxtSe = copyBytes(cipher.doFinal(Arrays.copyOfRange(txt, currTxt, txt.length - 1)), txtSe,
                        currTxtSe);
                // need to save exact number of bytes, so that they can be
                // de-serialized later
                encrypted.setCipherText(Arrays.copyOfRange(txtSe, 0, currTxtSe - 1));
            } else {
                throw new IdpEncryptionException("unsupported alogrithm type");
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpEncryptionException("encryption failed " + e.getMessage());
        }
        return encrypted;
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

    public IdpWrappedKeySpec wrap(IdpSecretKeySpec spec) {
        // initialize cipher with key spec in key wrap mode
        try {
            cipher.init(Cipher.WRAP_MODE, key);
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid secret key " + key);
        }
        IdpWrappedKeySpec wrappedKeySpec = new IdpWrappedKeySpec();
        wrappedKeySpec.setIv(cipher.getIV());
        wrappedKeySpec.setEncryptionAlgorithm(spec.getEncryptionAlgorithm());
        wrappedKeySpec.setKeyAlgorithm(spec.getKeyAlgorithm());
        wrappedKeySpec.setVersion(spec.getVersion());
        wrappedKeySpec.setKeyType(Cipher.SECRET_KEY);
        try {
            wrappedKeySpec.setKey(cipher
                    .wrap(new SecretKeySpec(Base64Utils.decodeFromString(spec.getKey()), spec.getKeyAlgorithm())));
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpEncryptionException("wrapping key failed " + e.getMessage());
        }
        return wrappedKeySpec;
    }

    private int copyBytes(byte[] from, byte[] to, int toStart) {
        for (int i = toStart; i < toStart + from.length; i++) {
            to[i] = from[i - toStart];
        }
        return toStart + from.length;
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

    public IdpSecretKeySpec unwrap(IdpWrappedKeySpec wrappedKeySpec) {
        // initialize cipher with key and IV in unwrap mode
        try {
            cipher.init(Cipher.UNWRAP_MODE, key, new IvParameterSpec(wrappedKeySpec.getIv()));
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid secret key " + key);
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IdpCryptoInitializationException("Invalid key algorithm " + e.getMessage());
        }
        IdpSecretKeySpec unwrappedKeySpec = new IdpSecretKeySpec();
        unwrappedKeySpec.setEncryptionAlgorithm(wrappedKeySpec.getEncryptionAlgorithm());
        unwrappedKeySpec.setKeyAlgorithm(wrappedKeySpec.getKeyAlgorithm());
        unwrappedKeySpec.setVersion(wrappedKeySpec.getVersion());
        try {
            unwrappedKeySpec.setKey(Base64Utils.encodeToString(cipher
                    .unwrap(wrappedKeySpec.getKey(), wrappedKeySpec.getKeyAlgorithm(), wrappedKeySpec.getKeyType())
                            .getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
            throw new IdpDecryptionException("unwrapping failed " + e.getMessage());
        }
        return unwrappedKeySpec;
    }
}
