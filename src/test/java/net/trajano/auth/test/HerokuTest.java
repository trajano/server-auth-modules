package net.trajano.auth.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

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
import net.trajano.auth.internal.JsonWebKeySet;
import net.trajano.auth.internal.OpenIDProviderConfiguration;
import net.trajano.auth.internal.TokenCookie;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.mockito.Mockito;
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
    @Test
    public void testConfig() throws Exception {
        final Client restClient = ClientBuilder.newClient();
        final OpenIDProviderConfiguration config = restClient
                .target("https://connect-op.heroku.com/.well-known/openid-configuration")
                .request().get(OpenIDProviderConfiguration.class);

        new JsonWebKeySet(restClient.target(config.getJwksUri()).request()
                .get(JsonObject.class));
    }

    /**
     * Test with the OREO test site. Ignored for now as <a
     * href="https://github.com/nov/openid_connect_sample_rp/issues/1">the
     * developer NOV for the heroku site refuses to provide assistance</a>.
     */
    @Test
    public void testWithTheModule() throws Exception {

        final WebDriver b = new FirefoxDriver();
        b.get("https://connect-op.heroku.com");
        b.findElement(By.name("commit")).click();
        b.findElement(By.linkText("Register New Client")).click();
        b.findElement(By.id("client_name")).sendKeys("Test");
        b.findElement(By.id("client_redirect_uri")).sendKeys(
                "https://www.trajano.net/app/oauth2");
        b.findElement(By.name("commit")).click();
        final Map<String, String> options;

        {
            final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
            options = new HashMap<>();
            options.put("client_id", b.findElement(By.xpath("//dd[1]"))
                    .getText());
            options.put("client_secret", b.findElement(By.xpath("//dd[2]"))
                    .getText());
            options.put("issuer_uri", "https://connect-op.heroku.com");
            options.put(OAuthModule.COOKIE_CONTEXT_KEY, "/");
            options.put(OAuthModule.REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2");

            final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
            when(mockRequestPolicy.isMandatory()).thenReturn(true);

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy, null, handler, options);

            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = Mockito
                    .mock(HttpServletRequest.class);
            when(req.getContextPath()).thenReturn("/app");
            when(req.isSecure()).thenReturn(true);
            when(req.getMethod()).thenReturn("GET");
            when(req.getRequestURL())
            .thenReturn(
                    new StringBuffer(
                            "https://www.trajano.net/app/somefile.jsp"));
            when(req.getRequestURI()).thenReturn("/app/somefile.jsp",
                    "/app/somefile.jsp");

            when(messageInfo.getRequestMessage()).thenReturn(req);

            final HttpServletResponse resp = mock(HttpServletResponse.class);

            when(messageInfo.getResponseMessage()).thenReturn(resp);

            final Subject client = new Subject();
            assertEquals(AuthStatus.SEND_CONTINUE,
                    module.validateRequest(messageInfo, client, null));
            final ArgumentCaptor<String> redirectUrl = ArgumentCaptor
                    .forClass(String.class);
            verify(resp).sendRedirect(redirectUrl.capture());
            b.get(redirectUrl.getValue());

            b.findElement(By.name("commit")).click();
            final WebDriverWait wait = new WebDriverWait(b, 30);
            wait.until(ExpectedConditions.invisibilityOfElementLocated(By
                    .name("commit")));
        }

        {
            final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();

            final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
            when(mockRequestPolicy.isMandatory()).thenReturn(true);

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy, null, handler, options);

            final String[] queryParams = URI.create(b.getCurrentUrl())
                    .getQuery().split("&");
            final String code = queryParams[0].substring(queryParams[0]
                    .indexOf('=') + 1);
            final String state = queryParams[1].substring(queryParams[1]
                    .indexOf('=') + 1);

            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = Mockito
                    .mock(HttpServletRequest.class);
            when(req.getContextPath()).thenReturn("/app");
            when(req.getRequestURL()).thenReturn(
                    new StringBuffer(b.getCurrentUrl()));
            when(req.getRequestURI()).thenReturn("/app/oauth2");
            when(req.getParameter("code")).thenReturn(code);
            when(req.getParameter("state")).thenReturn(state);
            when(req.getMethod()).thenReturn("GET");
            when(req.isSecure()).thenReturn(true);

            when(messageInfo.getRequestMessage()).thenReturn(req);

            final Subject client = new Subject();

            final HttpServletResponse resp = mock(HttpServletResponse.class);
            when(resp.encodeRedirectURL(Matchers.anyString())).then(
                    new Answer<String>() {

                        @Override
                        public String answer(final InvocationOnMock invocation)
                                throws Throwable {
                            final Object[] args = invocation.getArguments();
                            return (String) args[0];
                        }
                    });
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            assertEquals(AuthStatus.SEND_SUCCESS,
                    module.validateRequest(messageInfo, client, null));

            final ArgumentCaptor<Cookie> cookieCapture = ArgumentCaptor
                    .forClass(Cookie.class);
            verify(resp, times(2)).addCookie(cookieCapture.capture());
            final Cookie cookie = cookieCapture.getAllValues().get(0);
            assertEquals(OAuthModule.NET_TRAJANO_AUTH_ID, cookie.getName());
            final TokenCookie tokenCookie = new TokenCookie(cookie.getValue(),
                    options.get(OAuthModule.CLIENT_ID_KEY),
                    options.get(OAuthModule.CLIENT_SECRET_KEY));
            assertEquals("https://connect-op.heroku.com", tokenCookie
                    .getIdToken().getString("iss"));

            final Cookie ageCookie = cookieCapture.getAllValues().get(1);
            assertEquals(OAuthModule.NET_TRAJANO_AUTH_AGE, ageCookie.getName());

            final ArgumentCaptor<String> redirectUrl = ArgumentCaptor
                    .forClass(String.class);
            verify(resp).sendRedirect(redirectUrl.capture());
        }
        b.quit();
    }

    /**
     * Test with the OREO test site. Ignored for now as <a
     * href="https://github.com/nov/openid_connect_sample_rp/issues/1">the
     * developer NOV for the heroku site refuses to provide assistance</a>.
     */
    @Test
    @Ignore
    public void testWithTheModuleWithProfile() throws Exception {

        final WebDriver b = new FirefoxDriver();
        b.get("https://connect-op.heroku.com");
        b.findElement(By.name("commit")).click();
        b.findElement(By.linkText("Register New Client")).click();
        b.findElement(By.id("client_name")).sendKeys("Test");
        b.findElement(By.id("client_redirect_uri")).sendKeys(
                "https://www.trajano.net/app/oauth2");
        b.findElement(By.name("commit")).click();

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final Map<String, String> options = new HashMap<>();
        options.put("client_id", b.findElement(By.xpath("//dd[1]")).getText());
        options.put("client_secret", b.findElement(By.xpath("//dd[2]"))
                .getText());
        options.put("issuer_uri", "https://connect-op.heroku.com");
        options.put("scope", "openid profile");

        final CallbackHandler handler = mock(CallbackHandler.class);
        module.initialize(null, null, handler, options);

        {
            final MessageInfo messageInfo = Mockito.mock(MessageInfo.class);

            final HttpServletRequest req = Mockito
                    .mock(HttpServletRequest.class);
            when(req.getContextPath()).thenReturn("/app");
            when(req.getRequestURL())
            .thenReturn(
                    new StringBuffer(
                            "https://www.trajano.net/app/somefile.jsp"));

            when(messageInfo.getRequestMessage()).thenReturn(req);

            final HttpServletResponse resp = mock(HttpServletResponse.class);

            when(messageInfo.getResponseMessage()).thenReturn(resp);

            final Subject client = new Subject();
            Assert.assertEquals(AuthStatus.SEND_CONTINUE,
                    module.validateRequest(messageInfo, client, null));

            final ArgumentCaptor<String> redirectUrl = ArgumentCaptor
                    .forClass(String.class);
            verify(resp).sendRedirect(redirectUrl.capture());
            System.out.println(redirectUrl.getValue());

            b.get(redirectUrl.getValue());
            b.findElement(By.name("commit")).click();
            System.out.println(b.getCurrentUrl());
        }

        {

            final String[] queryParams = URI.create(b.getCurrentUrl())
                    .getQuery().split("&");
            final String code = queryParams[0].substring(queryParams[0]
                    .indexOf('=') + 1);
            final String state = queryParams[1].substring(queryParams[1]
                    .indexOf('=') + 1);

            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = Mockito
                    .mock(HttpServletRequest.class);
            when(req.getContextPath()).thenReturn("/app");
            when(req.getRequestURL()).thenReturn(
                    new StringBuffer("https://www.trajano.net/app/"));
            when(req.getParameter("code")).thenReturn(code);
            when(req.getParameter("state")).thenReturn(state);
            when(req.getMethod()).thenReturn("GET");
            when(req.isSecure()).thenReturn(true);

            when(messageInfo.getRequestMessage()).thenReturn(req);

            final Subject client = new Subject();

            final HttpServletResponse resp = mock(HttpServletResponse.class);
            when(resp.encodeRedirectURL(Matchers.anyString())).then(
                    new Answer<String>() {

                        @Override
                        public String answer(final InvocationOnMock invocation)
                                throws Throwable {
                            final Object[] args = invocation.getArguments();
                            return (String) args[0];
                        }
                    });
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            assertEquals(AuthStatus.SEND_SUCCESS,
                    module.validateRequest(messageInfo, client, null));

            final ArgumentCaptor<String> redirectUrl = ArgumentCaptor
                    .forClass(String.class);
            verify(resp).sendRedirect(redirectUrl.capture());

            final ArgumentCaptor<Cookie> cookieCapture = ArgumentCaptor
                    .forClass(Cookie.class);
            verify(resp).addCookie(cookieCapture.capture());
            final Cookie cookie = cookieCapture.getValue();
            assertEquals(OAuthModule.NET_TRAJANO_AUTH_ID, cookie.getName());
            final TokenCookie tokenCookie = new TokenCookie(cookie.getValue(),
                    options.get(OAuthModule.CLIENT_ID_KEY),
                    options.get(OAuthModule.CLIENT_SECRET_KEY));
            assertEquals("https://connect-op.heroku.com", tokenCookie
                    .getIdToken().getString("iss"));
            assertNotNull(tokenCookie.getUserInfo());
        }
        b.quit();
    }
}