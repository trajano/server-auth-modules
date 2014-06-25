package net.trajano.auth.internal;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

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
     * Prevent construction of utility class.
     */
    private JsonWebTokenUtil() {

    }
}
