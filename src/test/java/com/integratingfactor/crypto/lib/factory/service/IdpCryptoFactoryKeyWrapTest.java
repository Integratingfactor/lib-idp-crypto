package com.integratingfactor.crypto.lib.factory.service;

import java.security.Key;

import org.springframework.util.Base64Utils;
import org.testng.annotations.Test;
import org.testng.asserts.Assertion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.integratingfactor.crypto.lib.factory.model.IdpDecrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpWrappedKeySpec;
import com.integratingfactor.crypto.lib.factory.specs.IdpPbeKeySpec;
import com.integratingfactor.crypto.lib.factory.specs.IdpSecretKeySpec;

public class IdpCryptoFactoryKeyWrapTest extends Assertion {

    ObjectMapper mapper = new ObjectMapper();

    public static String TestPlainText = "*{ a secret }*";

    public static char[] TestPassPhrase2 = "this.is.second.pass.phrase".toCharArray();


    @Test
    public void testPbeKeySpecWrapUsingEncrypDecrypt() throws Exception {
        // get first PBE key spec instance
        IdpPbeKeySpec pbeKeySpec1 = IdpCryptoFactoryPbeTest.testIdpPbeKeySpec();

        // get an instance of the factory class
        IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();

        // initialize instance with first PBE key spec
        crypto.init(pbeKeySpec1, IdpCryptoFactoryPbeTest.TestPassPhrase);

        // encrypt data with first PBE key spec
        IdpEncrypted encrypted = crypto.encrypt(TestPlainText);
        System.out.println("Encrypted data: " + mapper.writeValueAsString(encrypted));

        // get the key corresponding to first PBE key spec
        Key pbeKey1 = crypto.getKey();

        // initialize crypto with second PBE key spec
        IdpPbeKeySpec pbeKeySpec2 = IdpCryptoFactoryPbeTest.testIdpPbeKeySpec();
        crypto.init(pbeKeySpec2, TestPassPhrase2);

        // verify that keys from 1st PBE key is different from 2nd PBE key
        assertNotEquals(crypto.getKey(), pbeKey1);

        // build new secret key spec using 1st PBE key spec's key
        IdpSecretKeySpec keySpec = new IdpSecretKeySpec();
        keySpec.setEncryptionAlgorithm(pbeKeySpec1.getEncryptionAlgorithm());
        keySpec.setKeyAlgorithm(pbeKeySpec1.getKeyAlgorithm());
        keySpec.setVersion(pbeKeySpec1.getVersion());
        keySpec.setKey(Base64Utils.encodeToString(pbeKey1.getEncoded()));

        // wrap secret key spec using 2nd PBE key spec
        IdpEncrypted wrappedKeySpec = crypto.encrypt(keySpec);
        System.out.println("Encrypted key spec: " + mapper.writeValueAsString(wrappedKeySpec));

        // unwrap key
        IdpDecrypted<IdpSecretKeySpec> unWrappedKeySpec = crypto.decrypt(wrappedKeySpec);
        System.out.println("Decrypted key spec: " + mapper.writeValueAsString(unWrappedKeySpec));

        // initialize crypto with unwrapped key
        crypto.init(unWrappedKeySpec.getData());

        // decrypt data with unwrapped key
        IdpDecrypted<String> data = crypto.decrypt(encrypted);
        System.out.println("Decrypted data: " + mapper.writeValueAsString(data));
        assertEquals(data.getData(), TestPlainText);
    }

    @Test
    public void testPbeKeySpecWrapUsingWrapUnwrap() throws Exception {
        // get first PBE key spec instance
        IdpPbeKeySpec pbeKeySpec1 = IdpCryptoFactoryPbeTest.testIdpPbeKeySpec();

        // get an instance of the factory class
        IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();

        // initialize instance with first PBE key spec
        crypto.init(pbeKeySpec1, IdpCryptoFactoryPbeTest.TestPassPhrase);

        // encrypt data with first PBE key spec
        IdpEncrypted encrypted = crypto.encrypt(TestPlainText);
        System.out.println("Encrypted data: " + mapper.writeValueAsString(encrypted));

        // get the key corresponding to first PBE key spec
        Key pbeKey1 = crypto.getKey();

        // initialize crypto with second PBE key spec
        IdpPbeKeySpec pbeKeySpec2 = IdpCryptoFactoryPbeTest.testIdpPbeKeySpec();
        crypto.init(pbeKeySpec2, TestPassPhrase2);

        // verify that keys from 1st PBE key is different from 2nd PBE key
        assertNotEquals(crypto.getKey(), pbeKey1);

        // build new secret key spec using 1st PBE key spec's key
        IdpSecretKeySpec keySpec = new IdpSecretKeySpec();
        keySpec.setEncryptionAlgorithm(pbeKeySpec1.getEncryptionAlgorithm());
        keySpec.setKeyAlgorithm(pbeKeySpec1.getKeyAlgorithm());
        keySpec.setVersion(pbeKeySpec1.getVersion());
        keySpec.setKey(Base64Utils.encodeToString(pbeKey1.getEncoded()));

        // wrap secret key spec using 2nd PBE key spec
        IdpWrappedKeySpec wrappedKeySpec = crypto.wrap(keySpec);
        System.out.println("Encrypted key spec: " + mapper.writeValueAsString(wrappedKeySpec));

        // unwrap key
        IdpSecretKeySpec unWrappedKeySpec = crypto.unwrap(wrappedKeySpec);
        System.out.println("Decrypted key spec: " + mapper.writeValueAsString(unWrappedKeySpec));

        // initialize crypto with unwrapped key
        crypto.init(unWrappedKeySpec);

        // decrypt data with unwrapped key
        IdpDecrypted<String> data = crypto.decrypt(encrypted);
        System.out.println("Decrypted data: " + mapper.writeValueAsString(data));
        assertEquals(data.getData(), TestPlainText);
    }
}
