package net.trajano.auth.internal;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import javax.json.Json;
import javax.json.JsonObject;

/**
 * Utility methods. Normally these would be in a separate JAR file like
 * commons-lang, but to prevent complications during installation such as
 * requiring to install additional JAR files, this class was created.
 *
 * @author Archimedes Trajano
 *
 */
public final class Utils {
    /**
     * Gets the JWT Claims Set from a JWT. It does parsing and validation of the
     * signatures based on the JsonWebKey and ensures the client ID is listed as
     * per the spec.
     *
     * @param token
     *            token
     * @param key
     *            JSON web key used to validate the token
     * @return the contents of the payload from the token
     * @throws GeneralSecurityException
     *             problem with crypto APIs
     */
    public static JsonObject getJwtClaimsSet(final String token,
            final JsonWebKey key) throws GeneralSecurityException {
        final String[] jwtParts = token.split("\\.");

        final JsonObject jwtHeader = Json.createReader(
                new ByteArrayInputStream(Base64.decode(jwtParts[0])))
                .readObject();

        // Handle plaintext JWTs
        if (!"none".equals(jwtHeader.getString("alg"))) {

            final String kid;
            if (jwtHeader.containsKey("kid")) {
                kid = jwtHeader.getString("kid");
            } else {
                kid = "";
            }
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
                throw new GeneralSecurityException(
                        "signature verification failed");
            }
        }
        final JsonObject jwtPayload = Json.createReader(
                new ByteArrayInputStream(Base64.decode(jwtParts[1])))
                .readObject();

        return jwtPayload;
    }

    /**
     * Checks if string is null or empty.
     *
     * @param s
     *            string to test
     * @return true if string is null or empty.
     */
    public static boolean isNullOrEmpty(final String s) {
        return s == null || s.trim().length() == 0;
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
    public static String toJavaAlgorithm(final String alg) {
        if ("RS256".equalsIgnoreCase(alg)) {
            return "SHA256withRSA";
        }
        return alg;
    }

    /**
     * Validates the ID Token.
     *
     * @param clientId
     *            client ID
     * @param idTokenJson
     *            ID Token JSON.
     * @throws GeneralSecurityException
     */
    public static void validateIdToken(final String clientId,
            final JsonObject idTokenJson) throws GeneralSecurityException {
        // TODO handle multiple audiences
        if (!clientId.equals(idTokenJson.getString("aud"))) {
            throw new GeneralSecurityException(String.format(
                    "invalid 'aud' got' %s' expected '%s'",
                    idTokenJson.getString("aud"), clientId));
        }
        if (idTokenJson.containsKey("azp")
                && !clientId.equals(idTokenJson.getString("azp"))) {
            throw new GeneralSecurityException(String.format(
                    "invalid 'azp' got' %s' expected '%s'",
                    idTokenJson.getString("azp"), clientId));
        }
        if (idTokenJson.containsKey("exp")
                && System.currentTimeMillis() > idTokenJson.getInt("exp") * 1000L) {
            throw new GeneralSecurityException("expired");
        }
    }

    /**
     * Prevent instantiation of utility class.
     */
    private Utils() {
    }
}
