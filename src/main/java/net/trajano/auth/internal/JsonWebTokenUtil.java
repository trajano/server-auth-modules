package net.trajano.auth.internal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;

/**
 * JSON Web Token utility class.
 *
 * @author Archimedes Trajano
 *
 */
public final class JsonWebTokenUtil {
    /**
     * Build secret key.
     *
     * @param clientId
     *            client ID
     * @param clientSecret
     *            client secret
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
     * Encrypts the payload. The encryption is based on a password based
     * encryption with the client secret and the password and the client ID as
     * the salt. It does not need to be too elaborate, just simple and fast.
     *
     * @param payload
     *            payload
     * @param clientId
     *            client ID
     * @param clientSecret
     *            clientSecret
     * @return encrypted payload
     * @throws GeneralSecurityException
     *             crypto API problem
     */
    public static String encryptPayload(final JsonObject payload,
            final String clientId, final String clientSecret)
                    throws GeneralSecurityException, IOException {
        final SecretKey secret = buildSecretKey(clientId, clientSecret);
        final Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        return Base64.encodeWithoutPadding(cipher.doFinal(payload.toString()
                .getBytes("UTF-8")));
    }

    /**
     * Gets the payload from the token. It does parsing and validation of the
     * signatures based on the JsonWebKey and ensures the client ID is listed as
     * per the spec.
     *
     * @param token
     *            token
     * @param key
     *            JSON web key used to validate the token
     * @param clientId
     *            client ID
     * @return the contents of the payload from the token
     * @throws GeneralSecurityException
     *             problem with crypto APIs
     */
    public static JsonObject getPayload(final String token,
            final JsonWebKey key, final String clientId)
            throws GeneralSecurityException {
        final String[] jwtParts = token.split("\\.");

        final JsonObject jwtHeader = Json.createReader(
                new ByteArrayInputStream(Base64.decode(jwtParts[0])))
                .readObject();

        final String kid = jwtHeader.getString("kid");
        final PublicKey signingKey = key.getKey(kid, PublicKey.class);

        if (signingKey == null) {
            throw new GeneralSecurityException("No key with id " + kid
                    + " defined");
        }

        final Signature signature = Signature
                .getInstance(toJavaAlgorithm(jwtHeader.getString("alg")));

        final byte[] jwtSignatureBytes = Base64.decode(jwtParts[2]);

        signature.initVerify(signingKey);
        signature.update((jwtParts[0] + "." + jwtParts[1]).getBytes());
        if (!signature.verify(jwtSignatureBytes)) {
            throw new GeneralSecurityException("signature verification failed");
        }

        final JsonObject jwtPayload = Json.createReader(
                new ByteArrayInputStream(Base64.decode(jwtParts[1])))
                .readObject();

        validatePayload(clientId, jwtPayload);

        return jwtPayload;
    }

    /**
     * Gets the payload from the token that was encoded and encrypted with a
     * secret key. The secret key is based on the clientSecret and clientId.
     *
     * @param token
     *            encoded and encrypted token
     * @param clientId
     *            client ID
     * @param clientSecret
     *            client secret
     * @return the contents of the payload from the token
     * @throws GeneralSecurityException
     *             problem with crypto APIs
     */
    public static JsonObject getPayload(final String token,
            final String clientId, final String clientSecret)
            throws GeneralSecurityException {

        final SecretKey secret = buildSecretKey(clientId, clientSecret);

        final Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secret);

        final JsonObject jwtPayload = Json.createReader(
                new ByteArrayInputStream(cipher.doFinal(Base64.decode(token))))
                .readObject();

        validatePayload(clientId, jwtPayload);

        return jwtPayload;
    }

    /**
     * Maps <a href=
     * "http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-29">JSON
     * Web Algorithm</a> names to <a href=
     * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html"
     * >Java Crypto</a> names. If the mapping is not known then the original
     * value is returned.
     *
     * @param alg
     *            algorithm name
     * @return algorithm name
     */
    private static String toJavaAlgorithm(final String alg) {
        if ("RS256".equalsIgnoreCase(alg)) {
            return "SHA256withRSA";
        }
        return alg;
    }

    /**
     * Validates the payload that was retrieved.
     *
     * @param clientId
     *            client ID
     * @param jwtPayload
     *            payload
     * @throws GeneralSecurityException
     */
    private static void validatePayload(final String clientId,
            final JsonObject jwtPayload) throws GeneralSecurityException {
        // TODO handle multiple audiences
        if (!clientId.equals(jwtPayload.getString("aud"))) {
            throw new GeneralSecurityException(String.format(
                    "invalid 'aud' got' %s' expected '%s'",
                    jwtPayload.getString("aud"), clientId));
        }
        if (jwtPayload.containsKey("azp")
                && !clientId.equals(jwtPayload.getString("azp"))) {
            throw new GeneralSecurityException(String.format(
                    "invalid 'azp' got' %s' expected '%s'",
                    jwtPayload.getString("azp"), clientId));
        }
        if (jwtPayload.containsKey("exp")
                && System.currentTimeMillis() > jwtPayload.getInt("exp") * 1000L) {
            throw new GeneralSecurityException("expired");
        }
    }

    /**
     * Prevent construction of utility class.
     */
    private JsonWebTokenUtil() {

    }
}
