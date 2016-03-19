package com.integratingfactor.crypto.lib.factory.model;

import java.io.Serializable;

public class IdpDecrypted<T extends Serializable> {

    T data;

    Integer keyVersion;

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public Integer getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(Integer keyVersion) {
        this.keyVersion = keyVersion;
    }

}
