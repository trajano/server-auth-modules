package net.trajano.auth.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.json.JsonObject;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;
import net.trajano.auth.internal.Base64;
import net.trajano.auth.internal.CipherUtil;
import net.trajano.auth.internal.JsonWebKeySet;
import net.trajano.auth.internal.OpenIDProviderConfiguration;
import net.trajano.auth.internal.TokenCookie;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * Tests using Heroku.
 */
public class HerokuTest {

    private Cookie ageCookie;

    private WebDriver b;

    private String clientId;

    private String clientSecret;

    private String finalUrl;

    private SecretKey secretKey;

    private TokenCookie tokenCookie;

    private MessagePolicy mockRequestPolicy() {

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);
        return mockRequestPolicy;
    }

    private HttpServletRequest mockRequestWithCurrentUrl() {

        return mockRequestWithUrl(b.getCurrentUrl());
    }

    private HttpServletRequest mockRequestWithUrl(final String urlString) {

        final HttpServletRequest req = mock(HttpServletRequest.class);
        final URI uri = URI.create(urlString);
        if (uri.getQuery() != null) {
            for (final String queryParam : uri.getQuery()
                    .split("&")) {
                when(req.getParameter(queryParam.substring(0, queryParam.indexOf('=')))).thenReturn(queryParam.substring(queryParam.indexOf('=') + 1));
                when(req.getRequestURL()).thenReturn(new StringBuffer(urlString.substring(0, urlString.indexOf("?"))));
            }
        } else {
            when(req.getRequestURL()).thenReturn(new StringBuffer(urlString));
        }
        when(req.getContextPath()).thenReturn("/app");
        when(req.isSecure()).thenReturn(true);
        when(req.getRemoteAddr()).thenReturn("8.8.8.8");
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn(uri.getPath());
        return req;
    }

    private HttpServletResponse mockResponse() {

        final HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.encodeRedirectURL(Matchers.anyString())).then(new Answer<String>() {

            @Override
            public String answer(final InvocationOnMock invocation) throws Throwable {

                final Object[] args = invocation.getArguments();
                return (String) args[0];
            }
        });
        return resp;
    }

    private void redirectFromResponse(final HttpServletResponse resp) throws IOException {

        final ArgumentCaptor<String> redirectUrl = ArgumentCaptor.forClass(String.class);
        verify(resp).sendRedirect(redirectUrl.capture());
        b.get(redirectUrl.getValue());

        b.findElement(By.name("commit"))
        .click();
        final WebDriverWait wait = new WebDriverWait(b, 30);
        wait.until(ExpectedConditions.invisibilityOfElementLocated(By.name("commit")));
    }

    @Before
    public void setUpBrowser() throws Exception {

        b = new FirefoxDriver();
        b.get("https://connect-op.herokuapp.com");
        b.findElement(By.name("commit"))
        .click();
        b.findElement(By.linkText("Register New Client"))
        .click();
        b.findElement(By.id("client_name"))
        .sendKeys("Test");
        b.findElement(By.id("client_redirect_uri"))
        .sendKeys("https://www.trajano.net/app/oauth2");
        b.findElement(By.name("commit"))
        .click();

        clientId = b.findElement(By.xpath("//dd[1]"))
                .getText();
        clientSecret = b.findElement(By.xpath("//dd[2]"))
                .getText();
        secretKey = CipherUtil.buildSecretKey(clientId, clientSecret);

    }

    @After
    public void tearDownBrowser() {

        b.quit();
    }

    @Test
    public void testConfig() throws Exception {

        final Client restClient = ClientBuilder.newClient();
        final OpenIDProviderConfiguration config = restClient.target("https://connect-op.herokuapp.com/.well-known/openid-configuration")
                .request()
                .get(OpenIDProviderConfiguration.class);

        new JsonWebKeySet(restClient.target(config.getJwksUri())
                .request()
                .get(JsonObject.class));
    }

    /**
     * Test with the OREO test site. Ignored for now as <a
     * href="https://github.com/nov/openid_connect_sample_rp/issues/1">the
     * developer NOV for the heroku site refuses to provide assistance</a>.
     */
    @Test
    public void testWithTheModule() throws Exception {

        final Map<String, String> options;

        {
            final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
            options = new HashMap<>();
            options.put("client_id", clientId);
            options.put("client_secret", clientSecret);
            options.put("issuer_uri", "https://connect-op.herokuapp.com");
            options.put(OAuthModule.COOKIE_CONTEXT_KEY, "/");
            options.put(OAuthModule.REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2");

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy(), null, handler, options);

            final MessageInfo messageInfo = mock(MessageInfo.class);
            final HttpServletRequest req = mockRequestWithUrl("https://www.trajano.net/app/foo.jsp");
            when(messageInfo.getRequestMessage()).thenReturn(req);

            final HttpServletResponse resp = mock(HttpServletResponse.class);
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            final Subject client = new Subject();
            assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
            redirectFromResponse(resp);
        }

        {
            final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy(), null, handler, options);

            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = mockRequestWithCurrentUrl();
            assertEquals("/foo.jsp", new String(Base64.decode(req.getParameter("state"))));
            when(messageInfo.getRequestMessage()).thenReturn(req);

            final Subject client = new Subject();

            final HttpServletResponse resp = mockResponse();
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));

            validateResponse(resp);
        }
    }

    /**
     * Test with the OREO test site. Ignored for now as <a
     * href="https://github.com/nov/openid_connect_sample_rp/issues/1">the
     * developer NOV for the heroku site refuses to provide assistance</a>.
     */
    @Test
    public void testWithTheModuleAndQueryString() throws Exception {

        final Map<String, String> options;
        {
            final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
            options = new HashMap<>();
            options.put("client_id", clientId);
            options.put("client_secret", clientSecret);
            options.put("issuer_uri", "https://connect-op.herokuapp.com");
            options.put(OAuthModule.COOKIE_CONTEXT_KEY, "/");
            options.put(OAuthModule.REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2");

            secretKey = CipherUtil.buildSecretKey(clientId, clientSecret);

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy(), null, handler, options);

            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = mock(HttpServletRequest.class);
            when(req.getContextPath()).thenReturn("/app", "/app");
            when(req.isSecure()).thenReturn(true);
            when(req.getMethod()).thenReturn("GET");
            when(req.getRequestURL()).thenReturn(new StringBuffer("https://www.trajano.net/app/somefile.jsp"));
            when(req.getQueryString()).thenReturn("q=foo");
            when(req.getRequestURI()).thenReturn("/app/somefile.jsp", "/app/somefile.jsp");

            when(messageInfo.getRequestMessage()).thenReturn(req);

            final HttpServletResponse resp = mock(HttpServletResponse.class);

            when(messageInfo.getResponseMessage()).thenReturn(resp);

            final Subject client = new Subject();
            assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
            redirectFromResponse(resp);
        }

        {
            final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();

            final MessagePolicy mockRequestPolicy = mockRequestPolicy();

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy, null, handler, options);

            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = mockRequestWithCurrentUrl();
            assertEquals("/somefile.jsp?q=foo", new String(Base64.decode(req.getParameter("state"))));

            when(messageInfo.getRequestMessage()).thenReturn(req);

            final Subject client = new Subject();

            final HttpServletResponse resp = mockResponse();
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));
            verify(req, times(2)).getParameter("code");
            verify(req, times(1)).getContextPath();

            validateResponse(resp);
            assertEquals("/app/somefile.jsp?q=foo", finalUrl);
            assertEquals("8.8.8.8", new String(CipherUtil.decrypt(Base64.decode(ageCookie.getValue()), secretKey)));
        }
    }

    /**
     * Test with the OREO test site. Ignored for now as <a
     * href="https://github.com/nov/openid_connect_sample_rp/issues/1">the
     * developer NOV for the heroku site refuses to provide assistance</a>.
     */
    @Test
    public void testWithTheModuleWithProfile() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final Map<String, String> options = new HashMap<>();
        options.put("client_id", clientId);
        options.put("client_secret", clientSecret);
        options.put("issuer_uri", "https://connect-op.herokuapp.com");
        options.put("scope", "openid profile");
        options.put(OAuthModule.REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2");
        final MessagePolicy mockRequestPolicy = mockRequestPolicy();

        final CallbackHandler handler = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, handler, options);

        {
            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = mockRequestWithUrl("https://www.trajano.net/app/somefile.jsp");
            when(messageInfo.getRequestMessage()).thenReturn(req);

            final HttpServletResponse resp = mock(HttpServletResponse.class);

            when(messageInfo.getResponseMessage()).thenReturn(resp);

            verify(resp, times(0)).sendError(Matchers.anyInt(), Matchers.anyString());
            final Subject client = new Subject();
            assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));

            redirectFromResponse(resp);
        }

        {
            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = mockRequestWithCurrentUrl();
            when(messageInfo.getRequestMessage()).thenReturn(req);

            final Subject client = new Subject();

            final HttpServletResponse resp = mockResponse();
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));

            validateResponse(resp);
            assertNotNull(tokenCookie.getUserInfo());
        }
    }

    private void validateResponse(final HttpServletResponse resp) throws GeneralSecurityException, IOException {

        final ArgumentCaptor<Cookie> cookieCapture = ArgumentCaptor.forClass(Cookie.class);
        verify(resp, times(3)).addCookie(cookieCapture.capture());
        final Cookie nonceCookie = cookieCapture.getAllValues()
                .get(0);
        assertEquals(OAuthModule.NET_TRAJANO_AUTH_NONCE, nonceCookie.getName());
        assertEquals(nonceCookie.getValue(), "");

        final Cookie cookie = cookieCapture.getAllValues()
                .get(1);
        assertEquals(OAuthModule.NET_TRAJANO_AUTH_ID, cookie.getName());
        tokenCookie = new TokenCookie(cookie.getValue(), secretKey);

        assertEquals("https://connect-op.herokuapp.com", tokenCookie.getIdToken()
                .getString("iss"));
        final String nonceCookieValue = Base64.encodeWithoutPadding(CipherUtil.encrypt(tokenCookie.getIdToken()
                .getString("nonce")
                .getBytes(), secretKey));
        assertEquals(8, Base64.decode(tokenCookie.getIdToken()
                .getString("nonce")).length);

        ageCookie = cookieCapture.getAllValues()
                .get(2);
        assertEquals(OAuthModule.NET_TRAJANO_AUTH_AGE, ageCookie.getName());

        final ArgumentCaptor<String> redirectUrl = ArgumentCaptor.forClass(String.class);
        verify(resp).sendRedirect(redirectUrl.capture());
        finalUrl = redirectUrl.getValue();
    }
}
