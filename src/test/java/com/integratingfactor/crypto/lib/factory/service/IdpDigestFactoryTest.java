package com.integratingfactor.crypto.lib.factory.service;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.integratingfactor.crypto.lib.factory.exceptions.IdpDigestException;

public class IdpDigestFactoryTest extends Assert {

    @Test
    public void testExceptionCheckInDigest() {
        try {
            IdpDigestFactory.getFingerPrint(null);
            fail("did not check exception");
        } catch (IdpDigestException e) {
            System.out.println(e);
        }
    }

    @Test
    public void testStringDigest() {
        String data = "a string with some characters to make it longer than 15 bytes, oops I mean 16 bytes";
        String fp1 = IdpDigestFactory.getFingerPrint(data);
        assertNotNull(fp1);
        String fp2 = IdpDigestFactory.getFingerPrint(data);
        assertNotNull(fp2);
        assertEquals(fp2, fp1);
        String fp3 = IdpDigestFactory.getFingerPrint(data.replace('a', 'z'));
        assertNotNull(fp3);
        assertNotEquals(fp3, fp1);
    }

    @Test
    public void testByteArrayDigest() {
        byte[] data = { 0x2c, 0x1a, 0x1b, 0x1c, 0x01, 0x00, 0x05, 0x23 };
        String fp1 = IdpDigestFactory.getFingerPrint(data);
        assertNotNull(fp1);
        String fp2 = IdpDigestFactory.getFingerPrint(data);
        assertNotNull(fp2);
        assertEquals(fp2, fp1);
        data[2] = 0x33;
        data[6] = 0x00;
        String fp3 = IdpDigestFactory.getFingerPrint(data);
        assertNotNull(fp3);
        assertNotEquals(fp3, fp1);
    }
}
