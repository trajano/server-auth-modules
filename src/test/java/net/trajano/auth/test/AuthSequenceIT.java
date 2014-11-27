package net.trajano.auth.test;

import static net.trajano.auth.OAuthModule.REDIRECTION_ENDPOINT_URI_KEY;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

public class AuthSequenceIT {

    @Test
    public void testRedirectToEndpoint() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();

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
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.isSecure()).thenReturn(true);

        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendRedirect("https://accounts.google.com/o/oauth2/auth?client_id=clientID&response_type=code&scope=openid&redirect_uri=https://i.trajano.net:8443/app/oauth2&state=L2VqYjI");
    }

    @Test
    public void testRedirectToEndpointWithQueryString() throws Exception {

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();

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
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getQueryString()).thenReturn("q=foo");
        when(servletRequest.isSecure()).thenReturn(true);

        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendRedirect("https://accounts.google.com/o/oauth2/auth?client_id=clientID&response_type=code&scope=openid&redirect_uri=https://i.trajano.net:8443/app/oauth2&state=L2VqYjI_cT1mb28");
    }
}
