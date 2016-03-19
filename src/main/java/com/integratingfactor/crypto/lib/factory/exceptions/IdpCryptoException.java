package com.integratingfactor.crypto.lib.factory.exceptions;

public abstract class IdpCryptoException extends RuntimeException {

    /**
     * 
     */
    private static final long serialVersionUID = 3900520433886719261L;
    private String error;

    protected IdpCryptoException(String error) {
        this.error = error;
    }

    public String getError() {
        return error;
    }

    @Override
    public String getMessage() {
        return error;
    }

}
