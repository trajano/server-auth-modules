package net.trajano.auth.internal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;

/**
 * Manages the token cookie.
 *
 * @author Archimedes
 *
 */
public class TokenCookie {
    /**
     * Cipher algorithm to use. "AES"
     */
    private static final String CIPHER_ALGORITHM = "AES";

    /**
     * Build secret key.
     *
     * @param clientId
     *            client ID (used for creating the {@link SecretKey})
     * @param clientSecret
     *            client secret (used for creating the {@link SecretKey})
     * @return a secret key
     * @throws GeneralSecurityException
     *             crypto API problem
     */
    public static SecretKey buildSecretKey(final String clientId,
            final String clientSecret) throws GeneralSecurityException {
        final PBEKeySpec pbeSpec = new PBEKeySpec(clientSecret.toCharArray(),
                clientId.getBytes(), 42, 128);

        final SecretKeyFactory factory = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA1");
        final SecretKey secret = new SecretKeySpec(factory.generateSecret(
                pbeSpec).getEncoded(), "AES");
        return secret;
    }

    /**
     * ID Token.
     */
    private final JsonObject idToken;

    /**
     * User info.
     */
    private final JsonObject userInfo;

    /**
     * Constructs with just the ID token.
     *
     * @param idToken
     *            ID token
     */
    public TokenCookie(final JsonObject idToken) {
        this(idToken, null);
    }

    /**
     * Constructs with the ID token and user info.
     *
     * @param idToken
     *            ID token
     * @param userInfo
     *            user info
     */
    public TokenCookie(final JsonObject idToken, final JsonObject userInfo) {
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    /**
     * Constructs with the cookie value.
     *
     * @param cookieValue
     *            cookie value
     * @param clientId
     *            client ID (used for creating the {@link SecretKey})
     * @param clientSecret
     *            client secret (used for creating the {@link SecretKey})
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public TokenCookie(final String cookieValue, final String clientId,
            final String clientSecret) throws IOException,
            GeneralSecurityException {
        final String[] cookieValues = cookieValue.split("\\.");
        final SecretKey secret = buildSecretKey(clientId, clientSecret);
        final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secret);

        idToken = Json.createReader(
                new GZIPInputStream(
                        new CipherInputStream(new ByteArrayInputStream(Base64
                                .decode(cookieValues[0])), cipher)))
                .readObject();
        if (cookieValues.length == 1) {
            userInfo = null;
        } else {
            userInfo = Json.createReader(
                    new GZIPInputStream(new CipherInputStream(
                            new ByteArrayInputStream(Base64
                                    .decode(cookieValues[1])), cipher)))
                    .readObject();
        }
    }

    /**
     * Encodes the JSON object to a Base64 string.
     *
     * @param jsonObject
     *            JSON obejct to encode
     * @param secret
     *            secret key
     * @return encoded JSON object.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private String encode(final JsonObject jsonObject, final SecretKey secret)
            throws IOException, GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secret);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream(2000);
        final OutputStream zos = new GZIPOutputStream(new CipherOutputStream(
                baos, cipher));
        zos.write(jsonObject.toString().getBytes("UTF-8"));
        zos.close();
        return Base64.encodeWithoutPadding(baos.toByteArray());
    }

    public JsonObject getIdToken() {
        return idToken;
    }

    /**
     * Returns the maximum age of the token.
     *
     * @return maximum age of the token
     */
    public int getMaxAge() {
        return idToken.getInt("exp")
                - (int) (System.currentTimeMillis() / 1000);
    }

    public JsonObject getUserInfo() {
        return userInfo;
    }

    /**
     * Converts to a cookie value.
     *
     * @param clientId
     *            client ID (used for creating the {@link SecretKey})
     * @param clientSecret
     *            client secret (used for creating the {@link SecretKey})
     * @return cookie value
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public String toCookieValue(final String clientId, final String clientSecret)
            throws IOException, GeneralSecurityException {
        final SecretKey secret = buildSecretKey(clientId, clientSecret);
        final StringBuilder b = new StringBuilder(encode(idToken, secret));
        if (userInfo != null) {
            b.append('.');
            b.append(encode(userInfo, secret));
        }
        return b.toString();
    }
}
