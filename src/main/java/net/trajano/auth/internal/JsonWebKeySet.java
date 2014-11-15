package net.trajano.auth.internal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.json.JsonObject;
import javax.json.JsonValue;

/**
 * JSON Web Key Set. Implements
 * http://tools.ietf.org/html/draft-ietf-jose-json-web-key-29 TODO when
 * supporting more methods, consider converting this to a composite pattern.
 *
 * @author Archimedes Trajano
 */
public class JsonWebKeySet {
    /**
     * Maps "kid" to the {@link Key}. Instances of this classes are short lived
     * and used in one thread context so concurrent use is not expected.
     */
    private final Map<String, Key> keyMap = new HashMap<>(); // NOPMD

    /**
     * Constructs the JSON Web Key using the JSON object. Unsupported key usage
     * scenarios are silently dropped.
     *
     * @param obj
     *            JSON object
     * @throws GeneralSecurityException
     *             problem with the crypto APIs
     */
    public JsonWebKeySet(final JsonObject obj) throws GeneralSecurityException {
        for (final JsonValue v : obj.getJsonArray("keys")) {
            final JsonObject keyJson = (JsonObject) v;
            final String kid;
            if (keyJson.containsKey("kid")) {
                kid = keyJson.getString("kid");
            } else {
                kid = "";
            }
            if (keyJson.containsKey("use") && "sig".equals(keyJson.getString("use"))) {
                final PublicKey key = buildPublicKey(keyJson);
                if (key != null) {
                    keyMap.put(kid, key);
                }
            }
        }
    }

    /**
     * This builds the {@link PublicKey} based on the "kty" value. Unsupported
     * key types are silently dropped.
     *
     * @param keyJson
     *            JSON object containing the key data
     * @return public key
     * @throws GeneralSecurityException
     *             problem with the crypto APIs
     */
    private PublicKey buildPublicKey(final JsonObject keyJson) throws GeneralSecurityException {
        final String kty = keyJson.getString("kty");
        if ("RSA".equals(kty)) {
            return buildRSAPublicKey(keyJson);
        }
        return null;
    }

    /**
     * Builds an RSA {@link PublicKey}. It uses "n" as the modulus and "e" as
     * the public exponent.
     *
     * @param keyJson
     *            JSON object containing the key data
     * @return public key
     * @throws GeneralSecurityException
     *             problem with the crypto APIs
     */
    private PublicKey buildRSAPublicKey(final JsonObject keyJson) throws GeneralSecurityException {
        final BigInteger modulus = new BigInteger(1, Base64.decode(keyJson.getString("n")));
        final BigInteger publicExponent = new BigInteger(1, Base64.decode(keyJson.getString("e")));
        return KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }

    /**
     * Gets a key given a Key ID.
     *
     * @param kid
     *            Key ID
     * @return key
     */
    public Key getKey(final String kid) {
        return keyMap.get(kid);
    }

    /**
     * Gets a key given a Key ID with a specified type.
     *
     * @param kid
     *            Key ID
     * @param clazz
     *            type of key.
     * @param <T>
     *            type
     * @return key
     */
    @SuppressWarnings("unchecked")
    public <T extends Key> T getKey(final String kid, final Class<T> clazz) {
        return (T) keyMap.get(kid);
    }
}
