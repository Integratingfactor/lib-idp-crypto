package com.integratingfactor.crypto.lib.factory.model;

import java.io.Serializable;

/**
 * encrypted cipher-text with IV and key version, can be stored as serialized
 * object in data stores
 * 
 * @author gnulib
 *
 */
public class IdpEncrypted implements Serializable{

    /**
     * 
     */
    private static final long serialVersionUID = -7213142591051449211L;

    byte[] cipherText;

    byte[] iv;

    Integer keyVersion;

    public byte[] getCipherText() {
        return cipherText;
    }

    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public Integer getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(Integer keyVersion) {
        this.keyVersion = keyVersion;
    }

}
