package net.trajano.auth.test;

import static org.junit.Assert.assertEquals;

import javax.json.Json;
import javax.json.JsonObject;

import net.trajano.auth.internal.CipherUtil;
import net.trajano.auth.internal.TokenCookie;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TokenCookieTest {

    private JsonObject idTokenJson;

    private JsonObject userInfoJson;

    @Before
    public void createJsons() {

        idTokenJson = Json.createObjectBuilder()
                .add("id", "token")
                .build();
        userInfoJson = Json.createObjectBuilder()
                .add("user", "info")
                .build();
    }

    @Test
    public void testConstructor() {

        Assert.assertNull(new TokenCookie(idTokenJson).getUserInfo());
    }

    @Test
    public void testConstructor2() {

        final JsonObject userInfo = new TokenCookie("access", null, idTokenJson, userInfoJson).getUserInfo();
        Assert.assertNotNull(userInfo);
        Assert.assertEquals(userInfo, userInfoJson);
    }

    @Test
    public void testExpiration() {

        System.out.println(1404851697 - (int) (System.currentTimeMillis() / 1000));
    }

    @Test
    public void testToCookieValueAndBack() throws Exception {

        final String cookieValue = new TokenCookie("access", "refresh", idTokenJson, userInfoJson).toCookieValue("clientId", "clientSecret");
        Assert.assertNotNull(cookieValue);

        final TokenCookie tokenCookie = new TokenCookie(cookieValue, CipherUtil.buildSecretKey("clientId", "clientSecret"));
        assertEquals(userInfoJson, tokenCookie.getUserInfo());
        assertEquals("access", tokenCookie.getAccessToken());
        assertEquals("refresh", tokenCookie.getRefreshToken());
    }
}
