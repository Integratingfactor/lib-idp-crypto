package com.integratingfactor.crypto.lib.factory.specs;

import java.io.Serializable;

/**
 * Definition class for password based encryption key used with IDP key vault
 * service
 * 
 * @author gnulib
 *
 */
public class IdpPbeKeySpec implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 6473321249158248421L;

    String encryptionAlgorithm;

    String keyAlgorithm;

    byte[] salt;

    Integer derivationCount;

    Integer keySize;

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

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public Integer getDerivationCount() {
        return derivationCount;
    }

    public void setDerivationCount(Integer derivationCount) {
        this.derivationCount = derivationCount;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

}
