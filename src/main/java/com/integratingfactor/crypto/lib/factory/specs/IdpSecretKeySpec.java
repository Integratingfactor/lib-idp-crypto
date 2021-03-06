package com.integratingfactor.crypto.lib.factory.specs;

import java.io.Serializable;

/**
 * Definition class for Secret Key used with IDP key vault service
 * 
 * @author gnulib
 *
 */
public class IdpSecretKeySpec implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -998877145232728690L;

    String encryptionAlgorithm;

    String keyAlgorithm;

    String key;

    Integer version;

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public void setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

}
