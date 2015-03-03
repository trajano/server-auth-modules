package net.trajano.auth.test;

import static com.google.common.base.Charsets.UTF_8;
import static javax.json.Json.createArrayBuilder;
import static javax.json.Json.createObjectBuilder;
import static net.trajano.auth.OAuthModule.REDIRECTION_ENDPOINT_URI_KEY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.net.HttpURLConnection;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonObject;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;

import net.trajano.auth.GoogleAuthModule;
import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;
import net.trajano.auth.internal.Base64;
import net.trajano.auth.internal.OAuthToken;
import net.trajano.auth.internal.OpenIDProviderConfiguration;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import com.google.common.collect.ImmutableMap;

public class AuthSequenceTest {

    /**
     * Google's OpenID Connect configuration.
     */
    private final OpenIDProviderConfiguration googleOpenIdConfiguration = new OpenIDProviderConfiguration(Json.createReader(Thread.currentThread()
            .getContextClassLoader()
            .getResourceAsStream("META-INF/google-config.json"))
            .readObject());

    /**
     * Module options.
     */
    private final Map<String, String> options = ImmutableMap.<String, String> builder()
            .put(OpenIDConnectAuthModule.ISSUER_URI_KEY, "https://accounts.google.com")
            .put(REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2")
            .put(OAuthModule.CLIENT_ID_KEY, "clientID")
            .put(OAuthModule.CLIENT_SECRET_KEY, "clientSecret")
            .build();

    /**
     * Posting data when unauthenticate is not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testFailUnauthenticatedPost() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        module.initialize(mockRequestPolicy, null, null, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("POST");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://i.trajano.net:8443/util/ejb2"));
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.isSecure()).thenReturn(true);

        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_FAILURE, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendError(eq(HttpURLConnection.HTTP_FORBIDDEN), anyString());
    }

    /**
     * Handles the callback operation.
     *
     * @throws Exception
     */
    @Test
    public void testHandleCallBack() throws Exception {

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        final KeyPair kp = kpg.genKeyPair();
        final String e = Base64.encodeWithoutPadding(((RSAPublicKey) kp.getPublic()).getPublicExponent()
                .toByteArray());
        final String n = Base64.encodeWithoutPadding(((RSAPublicKey) kp.getPublic()).getModulus()
                .toByteArray());

        final JsonObject jwks = createObjectBuilder().add("keys", createArrayBuilder().add(createObjectBuilder().add("kty", "RSA")
                .add("alg", "RS256")
                .add("use", "sig")
                .add("kid", "1234")
                .add("e", e)
                .add("n", n)))
                .build();

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();

        final Client mockRestClient = mock(Client.class);
        module.setRestClient(mockRestClient);
        final WebTarget openIdConfigurationTarget = mock(WebTarget.class);
        when(mockRestClient.target(URI.create("https://accounts.google.com/.well-known/openid-configuration"))).thenReturn(openIdConfigurationTarget);
        final Builder openIdConfigurationBuilder = mock(Builder.class);
        when(openIdConfigurationTarget.request(MediaType.APPLICATION_JSON_TYPE)).thenReturn(openIdConfigurationBuilder);

        when(openIdConfigurationBuilder.get(OpenIDProviderConfiguration.class)).thenReturn(googleOpenIdConfiguration);

        final WebTarget tokenEndpointTarget = mock(WebTarget.class);
        when(mockRestClient.target(googleOpenIdConfiguration.getTokenEndpoint())).thenReturn(tokenEndpointTarget);
        final Builder tokenEndpointBuilder = mock(Builder.class);
        when(tokenEndpointTarget.request(MediaType.APPLICATION_JSON_TYPE)).thenReturn(tokenEndpointBuilder);
        when(tokenEndpointBuilder.header(eq("Authorization"), anyString())).thenReturn(tokenEndpointBuilder);

        final OAuthToken oauthToken = new OAuthToken();

        final byte[] joseHeader = "{\"kid\":\"1234\",\"alg\":\"RS256\"}".getBytes(UTF_8);
        final byte[] claimsJson = ("{\"aud\":\"clientID\",\"azp\":\"clientID\",\"exp\":" + (System.currentTimeMillis() / 1000 + 86400) + ",\"iss\":\"accounts.google.com\",\"sub\":\"12312-2312\"}").getBytes(UTF_8);
        final Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update((Base64.encodeWithoutPadding(joseHeader) + "." + Base64.encodeWithoutPadding(claimsJson)).getBytes(UTF_8));
        final byte[] sigbytes = sig.sign();

        oauthToken.setIdToken(Base64.encodeWithoutPadding(joseHeader) + "." + Base64.encodeWithoutPadding(claimsJson) + "." + Base64.encodeWithoutPadding(sigbytes));

        when(tokenEndpointBuilder.post(any(Entity.class), eq(OAuthToken.class))).thenReturn(oauthToken);

        final WebTarget jwksTarget = mock(WebTarget.class);
        when(mockRestClient.target(googleOpenIdConfiguration.getJwksUri())).thenReturn(jwksTarget);
        final Builder jwksBuilder = mock(Builder.class);
        when(jwksTarget.request(MediaType.APPLICATION_JSON_TYPE)).thenReturn(jwksBuilder);

        when(jwksBuilder.get(JsonObject.class)).thenReturn(jwks);

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler handler = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, handler, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.getRemoteAddr()).thenReturn("8.8.8.8");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://i.trajano.net:8443/app/oauth2?code=SplxlOBeZQQYbYS6WxSbIA&state=L3V0aWwvZWpiMg"));
        when(servletRequest.getRequestURI()).thenReturn("/app/oauth2");
        when(servletRequest.getContextPath()).thenReturn("/myapp");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getParameter("code")).thenReturn("SplxlOBeZQQYbYS6WxSbIA");
        when(servletRequest.getParameter("state")).thenReturn("L3V0aWwvZWpiMg");

        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(servletResponse.encodeRedirectURL(anyString())).thenReturn("/util/ejb2");
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendRedirect("/util/ejb2");
        verify(handler).handle(any(Callback[].class));
    }

    /**
     * Tests callback validation.
     *
     * @throws Exception
     */
    @Test
    public void testIsCallback1() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        module.initialize(mockRequestPolicy, null, null, options);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://i.trajano.net:8443/util/ejb2"));
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.isSecure()).thenReturn(true);
        assertFalse(module.isCallback(servletRequest));
    }

    /**
     * Tests callback validation.
     *
     * @throws Exception
     */
    @Test
    public void testIsCallback2() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        module.initialize(mockRequestPolicy, null, null, options);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://i.trajano.net:8443/app/oauth2?code=1234&state=5678"));
        when(servletRequest.getRequestURI()).thenReturn("/app/oauth2");
        when(servletRequest.getParameter("code")).thenReturn("1234");
        when(servletRequest.getParameter("state")).thenReturn("5678");
        when(servletRequest.isSecure()).thenReturn(true);
        assertTrue(module.isCallback(servletRequest));
    }

    /**
     * The policy has determined it is not mandatory without SSL.
     *
     * @throws Exception
     */
    @Test
    public void testNoAuthNeededWithoutSSL() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final CallbackHandler h = mock(CallbackHandler.class);

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(false);

        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(false);
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SUCCESS, module.validateRequest(messageInfo, client, null));
        verifyZeroInteractions(h);
    }

    /**
     * The policy has determined it is not mandatory.
     *
     * @throws Exception
     */
    @Test
    public void testNoAuthNeededWithSSL() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final Client mockRestClient = mock(Client.class);
        module.setRestClient(mockRestClient);
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(false);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SUCCESS, module.validateRequest(messageInfo, client, null));
        verifyZeroInteractions(h, mockRestClient);
    }

    @Test
    public void testRedirectToEndpoint() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();

        final Client mockRestClient = mock(Client.class);
        module.setRestClient(mockRestClient);
        final WebTarget openIdConfigurationTarget = mock(WebTarget.class);
        when(mockRestClient.target(URI.create("https://accounts.google.com/.well-known/openid-configuration"))).thenReturn(openIdConfigurationTarget);
        final Builder openIdConfigurationBuilder = mock(Builder.class);
        when(openIdConfigurationTarget.request(MediaType.APPLICATION_JSON_TYPE)).thenReturn(openIdConfigurationBuilder);
        when(openIdConfigurationBuilder.get(OpenIDProviderConfiguration.class)).thenReturn(googleOpenIdConfiguration);

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);
        final Map<String, String> options = ImmutableMap.<String, String> builder()
                .put(OpenIDConnectAuthModule.ISSUER_URI_KEY, "https://accounts.google.com")
                .put(REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2")
                .put(OAuthModule.CLIENT_ID_KEY, "clientID")
                .put(OAuthModule.CLIENT_SECRET_KEY, "clientSecret")
                .build();
        module.initialize(mockRequestPolicy, null, null, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://i.trajano.net:8443/util/ejb2"));
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.isSecure()).thenReturn(true);

        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
        final ArgumentCaptor<String> redirectUriCaptor = ArgumentCaptor.forClass(String.class);
        verify(servletResponse).sendRedirect(redirectUriCaptor.capture());
        assertTrue(redirectUriCaptor.getValue()
                .startsWith("https://accounts.google.com/o/oauth2/auth?client_id=clientID&response_type=code&scope=openid&redirect_uri=https://i.trajano.net:8443/app/oauth2&state=L2VqYjI&nonce="));
    }

    @Test
    public void testSSLRequired() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        module.initialize(mockRequestPolicy, null, null, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(false);
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_FAILURE, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendError(HttpURLConnection.HTTP_FORBIDDEN, "SSL Required");
    }

    @Test
    public void testUseGoogle() throws Exception {

        final GoogleAuthModule module = new GoogleAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        module.initialize(mockRequestPolicy, null, null, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(false);
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_FAILURE, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendError(HttpURLConnection.HTTP_FORBIDDEN, "SSL Required");
    }
}
