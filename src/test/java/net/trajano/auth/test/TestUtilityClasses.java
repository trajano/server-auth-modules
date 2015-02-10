package net.trajano.auth.test;

import static net.trajano.auth.internal.Utils.isNullOrEmpty;
import static net.trajano.commons.testing.UtilityClassTestUtil.assertUtilityClassWellDefined;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;

import net.trajano.auth.internal.Base64;
import net.trajano.auth.internal.CipherUtil;
import net.trajano.auth.internal.OAuthParameters;
import net.trajano.auth.internal.Utils;

import org.junit.Test;

public class TestUtilityClasses {
    @Test
    public void testBase64() {
        assertArrayEquals(new byte[] {}, Base64.decode(Base64.encode(new byte[] {})));
        assertArrayEquals(new byte[] { 1 }, Base64.decode(Base64.encode(new byte[] { 1 })));
        assertArrayEquals(new byte[] { 1, 2 }, Base64.decode(Base64.encode(new byte[] { 1, 2 })));
        assertArrayEquals(new byte[] { 1, 2, 3 }, Base64.decode(Base64.encode(new byte[] { 1, 2, 3 })));
    }

    @Test
    public void testBase64Range() {
        final byte[] buf = new byte[] { 1, 2, 3 };
        assertArrayEquals(new byte[] {}, Base64.decode(Base64.encode(buf, 0, 0)));
        assertArrayEquals(new byte[] { 1 }, Base64.decode(Base64.encode(buf, 0, 1)));
        assertArrayEquals(new byte[] { 1, 2 }, Base64.decode(Base64.encode(buf, 0, 2)));
        assertArrayEquals(new byte[] { 1, 2, 3 }, Base64.decode(Base64.encode(buf, 0, 3)));
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        final SecretKey secret = CipherUtil.buildSecretKey("abc", "123");
        final byte[] clearText = "hello".getBytes();
        assertArrayEquals(clearText, CipherUtil.decrypt(CipherUtil.encrypt(clearText, secret), secret));
    }

    @Test
    public void testEncryptDecrypt2() throws Exception {
        final SecretKey secret = CipherUtil.buildSecretKey("abc", "123");
        final byte[] clearText = "hello".getBytes();
        final byte[] c1 = CipherUtil.encrypt(clearText, secret);
        final byte[] c2 = CipherUtil.encrypt(clearText, secret);
        assertArrayEquals(clearText, CipherUtil.decrypt(c1, secret));
        assertArrayEquals(clearText, CipherUtil.decrypt(c2, secret));
    }

    @Test
    public void testEncryptDecrypt3() throws Exception {
        final SecretKey secret = CipherUtil.buildSecretKey("abc", "123");
        final InputStream is = this.getClass()
                .getResourceAsStream("/googleopenidconfiguration.json");
        final Scanner scanner = new Scanner(is);
        final byte[] clearText = scanner.useDelimiter("\\A")
                .next()
                .getBytes();
        is.close();
        scanner.close();
        final byte[] c1 = CipherUtil.encrypt(clearText, secret);
        System.out.println(c1.length);
        assertArrayEquals(clearText, CipherUtil.decrypt(c1, secret));
    }

    @Test
    public void testIsNullOrEmpty() {
        assertTrue(isNullOrEmpty(null));
        assertTrue(isNullOrEmpty(""));
        assertTrue(isNullOrEmpty(" "));
        assertFalse(isNullOrEmpty("archie"));
    }

    @Test
    public void testRequestMethod() {
        final HttpServletRequest getRequest = mock(HttpServletRequest.class);
        when(getRequest.getMethod()).thenReturn("GET");

        final HttpServletRequest headRequest = mock(HttpServletRequest.class);
        when(headRequest.getMethod()).thenReturn("HEAD");

        final HttpServletRequest postRequest = mock(HttpServletRequest.class);
        when(postRequest.getMethod()).thenReturn("POST");

        assertTrue(Utils.isGetRequest(getRequest));
        assertFalse(Utils.isGetRequest(headRequest));
        assertFalse(Utils.isGetRequest(postRequest));

        assertFalse(Utils.isHeadRequest(getRequest));
        assertTrue(Utils.isHeadRequest(headRequest));
        assertFalse(Utils.isHeadRequest(postRequest));

        assertTrue(Utils.isRetrievalRequest(getRequest));
        assertTrue(Utils.isRetrievalRequest(headRequest));
        assertFalse(Utils.isRetrievalRequest(postRequest));
    }

    @Test
    public void validateUtilityClasses() throws Exception {
        assertUtilityClassWellDefined(OAuthParameters.class);
        assertUtilityClassWellDefined(Utils.class);
        assertUtilityClassWellDefined(CipherUtil.class);
        assertUtilityClassWellDefined(Base64.class);
    }
}
