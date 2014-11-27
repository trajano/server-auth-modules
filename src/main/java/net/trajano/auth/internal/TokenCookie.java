package net.trajano.auth.internal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonString;

/**
 * Manages the token cookie.
 *
 * @author Archimedes
 */
public class TokenCookie {

    /**
     * Access token key in the tokens structure.
     */
    private static final String ACCESS_TOKEN_KEY = "a";

    /**
     * Refresh token key in the tokens structure.
     */
    private static final String REFRESH_TOKEN_KEY = "r";

    /**
     * Access Token.
     */
    private final String accessToken;

    /**
     * ID Token.
     */
    private final JsonObject idToken;

    /**
     * Refresh Token.
     */
    private final String refreshToken;

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

        this("", "", idToken, null);
    }

    /**
     * Constructs with the cookie value.
     *
     * @param cookieValue
     *            cookie value
     * @param secret
     *            secret key
     * @throws GeneralSecurityException
     */
    public TokenCookie(final String cookieValue, final SecretKey secret) throws GeneralSecurityException {

        final String[] cookieValues = cookieValue.split("\\.");

        try {
            final JsonObject tokens = Json.createReader(CipherUtil.buildDecryptStream(new ByteArrayInputStream(Base64.decode(cookieValues[0])), secret))
                    .readObject();
            accessToken = ((JsonString) tokens.get(ACCESS_TOKEN_KEY)).getString();
            refreshToken = ((JsonString) tokens.get(REFRESH_TOKEN_KEY)).getString();
            idToken = Json.createReader(CipherUtil.buildDecryptStream(new ByteArrayInputStream(Base64.decode(cookieValues[1])), secret))
                    .readObject();
            if (cookieValues.length == 2) {
                userInfo = null;
            } else {
                userInfo = Json.createReader(CipherUtil.buildDecryptStream(new ByteArrayInputStream(Base64.decode(cookieValues[2])), secret))
                        .readObject();
            }
        } catch (final IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * Constructs with the ID token and user info.
     *
     * @param idToken
     *            ID token
     * @param userInfo
     *            user info
     */
    public TokenCookie(final String accessToken, final String refreshToken, final JsonObject idToken, final JsonObject userInfo) {

        this.accessToken = accessToken;
        this.refreshToken = refreshToken != null ? refreshToken : "";
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    /**
     * Encodes the JSON object to a Base64 string.
     *
     * @param jsonObject
     *            JSON obejct to encode
     * @param secret
     *            secret key
     * @return encoded JSON object.
     * @throws GeneralSecurityException
     */
    private String encode(final JsonObject jsonObject,
            final SecretKey secret) throws GeneralSecurityException {

        try {
            return Base64.encodeWithoutPadding(CipherUtil.encrypt(jsonObject.toString()
                    .getBytes("UTF-8"), secret));
        } catch (final IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    public String getAccessToken() {

        return accessToken;
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

        return idToken.getInt("exp") - (int) (System.currentTimeMillis() / 1000);
    }

    public String getRefreshToken() {

        return refreshToken;
    }

    public JsonObject getUserInfo() {

        return userInfo;
    }

    public boolean isExpired() {

        return idToken.getInt("exp") < System.currentTimeMillis() / 1000;
    }

    /**
     * Converts to a cookie value.
     *
     * @param clientId
     *            client ID (used for creating the {@link SecretKey})
     * @param clientSecret
     *            client secret (used for creating the {@link SecretKey})
     * @return cookie value
     * @throws GeneralSecurityException
     */
    public String toCookieValue(final String clientId,
            final String clientSecret) throws GeneralSecurityException {

        final SecretKey secret = CipherUtil.buildSecretKey(clientId, clientSecret);
        final JsonObject tokens = Json.createObjectBuilder()
                .add(ACCESS_TOKEN_KEY, accessToken)
                .add(REFRESH_TOKEN_KEY, refreshToken)
                .build();

        final StringBuilder b = new StringBuilder(encode(tokens, secret));
        b.append('.');
        b.append(encode(idToken, secret));
        if (userInfo != null) {
            b.append('.');
            b.append(encode(userInfo, secret));
        }
        return b.toString();
    }
}
