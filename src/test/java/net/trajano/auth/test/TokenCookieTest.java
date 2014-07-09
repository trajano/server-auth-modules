package net.trajano.auth.test;

import javax.json.Json;
import javax.json.JsonObject;

import net.trajano.auth.internal.TokenCookie;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TokenCookieTest {

    private JsonObject idTokenJson;
    private JsonObject userInfoJson;

    @Before
    public void createJsons() {
        idTokenJson = Json.createObjectBuilder().add("id", "token").build();
        userInfoJson = Json.createObjectBuilder().add("user", "info").build();
    }

    @Test
    public void testConstructor() {
        Assert.assertNull(new TokenCookie(idTokenJson).getUserInfo());
    }

    @Test
    public void testConstructor2() {
        final JsonObject userInfo = new TokenCookie(idTokenJson, userInfoJson)
        .getUserInfo();
        Assert.assertNotNull(userInfo);
        Assert.assertEquals(userInfo, userInfoJson);
    }

    @Test
    public void testExpiration() {
        System.out
        .println(1404851697 - (int) (System.currentTimeMillis() / 1000));
    }

    @Test
    public void testToCookieValueAndBack() throws Exception {
        final String cookieValue = new TokenCookie(idTokenJson, userInfoJson)
        .toCookieValue("clientId", "clientSecret");
        Assert.assertNotNull(cookieValue);

        final JsonObject userInfo = new TokenCookie(cookieValue, "clientId",
                "clientSecret").getUserInfo();
        Assert.assertEquals(userInfo, userInfoJson);
    }
}
