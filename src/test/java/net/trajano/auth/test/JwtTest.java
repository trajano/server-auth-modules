package net.trajano.auth.test;

import static javax.json.Json.createArrayBuilder;
import static javax.json.Json.createObjectBuilder;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import javax.json.Json;
import javax.json.stream.JsonParsingException;

import net.trajano.auth.internal.Base64;
import net.trajano.auth.internal.JsonWebAlgorithm;
import net.trajano.auth.internal.JsonWebKeySet;
import net.trajano.auth.internal.Utils;

import org.junit.Before;
import org.junit.Test;

import com.google.common.base.Charsets;

public class JwtTest {
    private JsonWebKeySet jwks;
    private PrivateKey privateKey;

    @Before
    public void setKeys() throws GeneralSecurityException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair kp = kpg.genKeyPair();
        final String e = Base64.encodeWithoutPadding(((RSAPublicKey) kp.getPublic()).getPublicExponent()
                .toByteArray());
        final String n = Base64.encodeWithoutPadding(((RSAPublicKey) kp.getPublic()).getModulus()
                .toByteArray());
        privateKey = kp.getPrivate();
        jwks = new JsonWebKeySet(createObjectBuilder().add("keys", createArrayBuilder().add(createObjectBuilder().add("kty", "RSA")
                .add("alg", "RS256")
                .add("use", "sig")
                .add("kid", "1234")
                .add("e", e)
                .add("n", n)))
                .build());
    }

    @Test
    public void testEnum() {
        assertEquals(JsonWebAlgorithm.RS256, Enum.valueOf(JsonWebAlgorithm.class, "RS256"));
    }

    @Test(expected = JsonParsingException.class)
    public void testInvalidToken() throws Exception {
        Utils.getJwsPayload("ABCD", jwks);
    }

    @Test
    public void testNoCryptoToken() throws Exception {
        final String joseHeader = "{\"alg\":\"none\"}";
        final byte[] message = "HELLO".getBytes("UTF-8");

        final byte[] jwsPayload = Utils.getJwsPayload(Base64.encodeWithoutPadding(joseHeader.getBytes("UTF-8")) + "." + Base64.encodeWithoutPadding(message), jwks);
        assertArrayEquals(message, jwsPayload);
    }

    @Test
    public void testSignedToken() throws Exception {
        final String joseHeader = "{\"kid\":\"1234\",\"alg\":\"RS256\"}";
        final byte[] message = "HELLO".getBytes("UTF-8");
        final Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update((Base64.encodeWithoutPadding(joseHeader.getBytes("UTF-8")) + "." + Base64.encodeWithoutPadding(message)).getBytes("UTF-8"));
        final byte[] sigbytes = sig.sign();

        final byte[] jwsPayload = Utils.getJwsPayload(Base64.encodeWithoutPadding(joseHeader.getBytes("UTF-8")) + "." + Base64.encodeWithoutPadding(message) + "." + Base64.encodeWithoutPadding(sigbytes), jwks);
        assertArrayEquals(message, jwsPayload);
    }

    @Test
    public void testWithGoogleData() throws Exception {
        final JsonWebKeySet jwks = new JsonWebKeySet(Json.createReader(Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("googlecerts.json"))
                .readObject());
        final BufferedReader reader = new BufferedReader(new InputStreamReader(Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("jwt.txt")));
        System.out.println(new String(Utils.getJwsPayload(reader.readLine(), jwks), Charsets.UTF_8));
    }
}
