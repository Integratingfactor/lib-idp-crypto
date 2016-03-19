package com.integratingfactor.crypto.lib.factory.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.springframework.util.Base64Utils;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.testng.asserts.Assertion;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.integratingfactor.crypto.lib.factory.model.IdpDecrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
import com.integratingfactor.crypto.lib.factory.specs.IdpSecretKeySpec;

public class IdpCryptoFactoryTest extends Assertion {

    ObjectMapper mapper = new ObjectMapper();

    public static String TestEncryptionAlgorithm = "AES/CBC/PKCS5Padding";

    public static String TestKeyGenerationAlgorithm = "AES";

    public static Integer TestKeyVersion = 1;

    public static String TestPlainText = "*{ a secret }*";

    public static SecretKey testSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(TestKeyGenerationAlgorithm);
        return keygen.generateKey();
    }

    public static IdpSecretKeySpec testIdpSecretKeySpec() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKey key = IdpCryptoFactoryTest.testSecretKey();
        IdpSecretKeySpec specs = new IdpSecretKeySpec();
        specs.setEncryptionAlgorithm(TestEncryptionAlgorithm);
        specs.setKeyAlgorithm(key.getAlgorithm());
        specs.setVersion(TestKeyVersion);
        specs.setKey(Base64Utils.encodeToString(key.getEncoded()));
        Assert.assertEquals(key.getEncoded(), Base64Utils.decodeFromString(specs.getKey()));
        return specs;
    }

    @Test
    public void testGetInstance() {
        assertNotNull(IdpCryptoFactory.getInstance());
    }

    @Test
    public void testInitialization() throws NoSuchAlgorithmException, InvalidKeySpecException, JsonProcessingException,
            NoSuchPaddingException, InvalidKeyException {
        // get factory instance
        IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();

        // get test encryption key
        IdpSecretKeySpec spec = IdpCryptoFactoryTest.testIdpSecretKeySpec();
        System.out.println("Got key specs: " + mapper.writeValueAsString(spec));

        // initialize factory instance with key definition
        crypto.init(spec);
        System.out.println("Initialized cipher: " + mapper.writeValueAsString(crypto.cipher.getParameters()));

        // make sure cipher is initialized
        assertNotNull(crypto.cipher);
        assertEquals(crypto.cipher.getAlgorithm(), TestEncryptionAlgorithm);
    }

    @Test
    public void testEncryptionMethod() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
            InvalidKeySpecException, JsonProcessingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        // get an instance of the factory class
        IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();

        // initialize instance with IDP key definition
        crypto.init(IdpCryptoFactoryTest.testIdpSecretKeySpec());

        // run encryption of data
        IdpEncrypted encrypted = crypto.encrypt(TestPlainText);
        System.out.println("Encrypted: " + mapper.writeValueAsString(encrypted));
        assertNotNull(encrypted);
        assertNotNull(encrypted.getCipherText());
        assertNotNull(crypto.cipher.getIV());
        assertEquals(encrypted.getIv(), crypto.cipher.getIV());
        assertNotNull(encrypted.getKeyVersion());
    }

    @Test
    public void testDecryptionMethod() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            ClassNotFoundException, IOException {
        // get an instance of the factory class
        IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();

        // initialize instance with IDP key definition
        crypto.init(IdpCryptoFactoryTest.testIdpSecretKeySpec());

        // run an encryption, and then decrypt
        IdpDecrypted<String> decrypted = crypto.decrypt(crypto.encrypt(TestPlainText));
        System.out.println("Decrypted: " + mapper.writeValueAsString(decrypted));

        // validated that we got what we encrypted
        assertEquals(decrypted.getData(), TestPlainText);
    }
}
