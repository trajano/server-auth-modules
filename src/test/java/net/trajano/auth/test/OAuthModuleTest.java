package net.trajano.auth.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;

import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;
import net.trajano.auth.internal.Base64;
import net.trajano.auth.internal.JsonWebTokenUtil;

import org.junit.Test;

/**
 * Tests the OAuthModule.
 */
public class OAuthModuleTest {

    @Test
    public void testCompressDecompress() throws Exception {
        final String payload = "foo";
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final GZIPOutputStream os = new GZIPOutputStream(baos);
        os.write(payload.toString().getBytes("UTF-8"));
        System.out.println(baos.toByteArray().length);
        os.close();
        final String encoded = Base64.encodeWithoutPadding(baos.toByteArray());

        final GZIPInputStream is = new GZIPInputStream(
                new ByteArrayInputStream(Base64.decode(encoded)));
        @SuppressWarnings("resource")
        final String decoded = new Scanner(is).useDelimiter("\\A").next();
        is.close();
        assertEquals(payload, decoded);
    }

    /**
     * Tests getting the configuration from Google.
     *
     * @throws Exception
     */
    @Test
    public void testGoogleOpenIdConfiguration() throws Exception {
        final Map<String, String> options = new HashMap<>();
        options.put(OAuthModule.CLIENT_ID_KEY, "clientID");
        options.put(OAuthModule.CLIENT_SECRET_KEY, "clientSecret");
        options.put(OpenIDConnectAuthModule.ISSUER_URI_KEY,
                "https://accounts.google.com/");

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        module.initialize(null, null, null, options);
    }

    @Test
    public void testPasswordBasedEncryption() throws Exception {
        final String issuer = "http://accounts.google.com/";
        final String clientSecret = "05_rL1ENVlOGi-E848mb-rSJ";
        final PBEKeySpec spec = new PBEKeySpec(clientSecret.toCharArray(),
                issuer.getBytes(), 42, 256);

        final PBEKeySpec spec1 = new PBEKeySpec(clientSecret.toCharArray(),
                issuer.getBytes(), 42, 256);

        final PBEKeySpec spec2 = new PBEKeySpec("foo".toCharArray(),
                issuer.getBytes(), 42, 256);

        final SecretKeyFactory factory = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA1");
        final SecretKey tmp = factory.generateSecret(spec);
        final SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        final SecretKey tmp1 = factory.generateSecret(spec1);
        final SecretKey secret1 = new SecretKeySpec(tmp1.getEncoded(), "AES");

        final SecretKey tmp2 = factory.generateSecret(spec2);
        final SecretKey secret2 = new SecretKeySpec(tmp2.getEncoded(), "AES");

        final byte[] encoded;
        {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            encoded = cipher.doFinal(issuer.getBytes());
        }
        {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret);
            assertArrayEquals(issuer.getBytes(), cipher.doFinal(encoded));
        }
        {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret1);
            assertArrayEquals(issuer.getBytes(), cipher.doFinal(encoded));
        }
        try {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret2);
            cipher.doFinal(encoded);
            fail();
        } catch (final BadPaddingException e) {

        }
    }

    @Test
    public void testPasswordBasedEncryption2() throws Exception {
        final String issuer = "http://accounts.google.com/";
        final String clientSecret = "05_rL1ENVlOGi-E848mb-rSJ";

        final PBEKeySpec spec2 = new PBEKeySpec("foo".toCharArray(),
                issuer.getBytes(), 42, 256);

        final SecretKeyFactory factory = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA1");

        final SecretKey secret = JsonWebTokenUtil.buildSecretKey("clientId",
                clientSecret);

        final SecretKey secret1 = JsonWebTokenUtil.buildSecretKey("clientId",
                clientSecret);

        final SecretKey tmp2 = factory.generateSecret(spec2);
        final SecretKey secret2 = new SecretKeySpec(tmp2.getEncoded(), "AES");

        final byte[] encoded;
        {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            encoded = cipher.doFinal(issuer.getBytes());
        }
        {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret);
            assertArrayEquals(issuer.getBytes(), cipher.doFinal(encoded));
        }
        {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret1);
            assertArrayEquals(issuer.getBytes(), cipher.doFinal(encoded));
        }
        try {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secret2);
            cipher.doFinal(encoded);
            fail();
        } catch (final BadPaddingException e) {

        }
    }

    @Test
    public void testPayloadEncryptDecrypt() throws Exception {
        final String encryptPayload = JsonWebTokenUtil.encryptPayload(
                Json.createReader(
                        new ByteArrayInputStream("{\"aud\":\"clientID\"}"
                                .getBytes())).readObject(), "clientID",
                "clientSecret");
        JsonWebTokenUtil.getPayload(encryptPayload, "clientID", "clientSecret");
    }

    /**
     * Tests getting the configuration from Salesforce.
     *
     * @throws Exception
     */
    @Test
    public void testSalesforceOpenIdConfiguration() throws Exception {
        final Map<String, String> options = new HashMap<>();
        options.put(OAuthModule.CLIENT_ID_KEY, "clientID");
        options.put(OAuthModule.CLIENT_SECRET_KEY, "clientSecret");
        options.put(OpenIDConnectAuthModule.ISSUER_URI_KEY,
                "https://login.salesforce.com");

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        module.initialize(null, null, null, options);
    }
}