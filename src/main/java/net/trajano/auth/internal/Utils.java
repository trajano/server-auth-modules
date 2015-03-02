package net.trajano.auth.internal;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;

/**
 * Utility methods. Normally these would be in a separate JAR file like
 * commons-lang, but to prevent complications during installation such as
 * requiring to install additional JAR files, this class was created.
 *
 * @author Archimedes Trajano
 */
public final class Utils {
    /**
     * Logger.
     */
    private static final Logger LOG;

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    static {
        LOG = Logger.getLogger("net.trajano.auth.oauthsam", MESSAGES);
    }

    /**
     * Gets the JWS Payload from a <a href=
     * "http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-30#section-3.1"
     * >JWS Compact Serialization</a>. The validation follows the rules in <a
     * href=
     * "http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-30#section-5.2"
     * >Message Signature or MAC validation section of JSON Web Signature</a>.
     * <p>
     * Note that "jku", "jwk", "x5u" and "x5c" should nor will <b>never</b> be
     * implemented. It does not make sense for the serialization to contain its
     * own validation.
     *
     * @param serialization
     *            JWS compact serialization
     * @param keyset
     *            JSON web key used to validate the token
     * @return the JWS payload
     * @throws GeneralSecurityException
     *             problem with crypto APIs or signature was not valid
     */
    public static byte[] getJwsPayload(final String serialization, final JsonWebKeySet keyset) throws GeneralSecurityException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("serialized payload = " + serialization);
        }
        final String[] jwtParts = serialization.split("\\.");

        final JsonObject joseHeader = Json.createReader(new ByteArrayInputStream(Base64.decode(jwtParts[0])))
                .readObject();

        // Handle plaintext JWTs
        if (!"none".equals(joseHeader.getString("alg"))) {

            final String kid;
            if (joseHeader.containsKey("kid")) {
                kid = joseHeader.getString("kid");
            } else {
                kid = "";
            }
            final PublicKey signingKey = keyset.getKey(kid, PublicKey.class);

            if (signingKey == null) {
                throw new GeneralSecurityException("No key with id " + kid + " defined");
            }

            final Signature signature = Signature.getInstance(toJavaAlgorithm(joseHeader.getString("alg")));

            final byte[] jwtSignatureBytes = Base64.decode(jwtParts[2]);

            signature.initVerify(signingKey);
            signature.update((jwtParts[0] + "." + jwtParts[1]).getBytes());
            if (!signature.verify(jwtSignatureBytes)) {
                throw new GeneralSecurityException("signature verification failed");
            }
        }
        return Base64.decode(jwtParts[1]);
    }

    /**
     * Checks if the request uses the GET method.
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the GET method.
     */
    public static boolean isGetRequest(final HttpServletRequest req) {
        return "GET".equals(req.getMethod());
    }

    /**
     * Checks if the request uses the HEAD method.
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the HEAD method.
     */
    public static boolean isHeadRequest(final HttpServletRequest req) {
        return "HEAD".equals(req.getMethod());
    }

    /**
     * Checks if string is null or empty.
     *
     * @param s
     *            string to test
     * @return true if string is null or empty.
     */
    public static boolean isNullOrEmpty(final String s) {
        return s == null || s.trim()
                .length() == 0;
    }

    /**
     * Checks if the request is to retrieve data (i.e. "GET" or "HEAD" method).
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the GET or HEAD method.
     */
    public static boolean isRetrievalRequest(final HttpServletRequest req) {
        return isGetRequest(req) || isHeadRequest(req);
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
        return JsonWebAlgorithm.valueOf(alg)
                .toJca();
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
    public static void validateIdToken(final String clientId, final JsonObject idTokenJson, final String nonce) throws GeneralSecurityException {
        // TODO handle multiple audiences
        if (!clientId.equals(idTokenJson.getString("aud"))) {
            throw new GeneralSecurityException(String.format("invalid 'aud' got' %s' expected '%s'", idTokenJson.getString("aud"), clientId));
        }
        if (nonce != null && !nonce.equals(idTokenJson.getString("nonce"))) {
            throw new GeneralSecurityException(String.format("invalid 'nonce' got' %s' expected '%s'", idTokenJson.getString("nonce"), clientId));
        }
        if (idTokenJson.containsKey("azp") && !clientId.equals(idTokenJson.getString("azp"))) {
            throw new GeneralSecurityException(String.format("invalid 'azp' got' %s' expected '%s'", idTokenJson.getString("azp"), clientId));
        }
        if (idTokenJson.containsKey("exp")) {
            final long delta = System.currentTimeMillis() - idTokenJson.getInt("exp") * 1000L;
            if (delta >= 0) {
                throw new GeneralSecurityException("expired " + delta + "ms ago");
            }
        }
    }

    /**
     * Prevent instantiation of utility class.
     */
    private Utils() {
    }
}
