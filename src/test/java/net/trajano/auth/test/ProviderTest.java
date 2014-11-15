package net.trajano.auth.test;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.ServerAuthConfig;

import net.trajano.auth.AuthModuleConfigProvider;
import net.trajano.auth.OpenIDConnectAuthModule;

import org.junit.Test;
import org.mockito.Mockito;

public class ProviderTest {
    @Test
    public void testOpenIDConfigProvider() throws Exception {
        final Map<String, String> options = new HashMap<>();
        // options.put(ConfigProvider.LAYER, "HttpServlet");
        options.put(AuthModuleConfigProvider.SERVER_AUTH_MODULE_CLASS, OpenIDConnectAuthModule.class.getName());
        options.put("client_id", "angelstone-client-id");
        options.put("client_secret", "angelstone-client-secret-change-this");
        options.put("cookie_context", "/");
        options.put("issuer_uri", "https://localhost:8181/");
        options.put("scope", "openid profile email");
        options.put("redirection_endpoint", "/app/oauth2");
        options.put("token_uri", "/app/token");
        options.put("userinfo_uri", "/app/userinfo");
        final AuthModuleConfigProvider provider = new AuthModuleConfigProvider(options, AuthConfigFactory.getFactory());
        final ServerAuthConfig serverAuthConfig = provider.getServerAuthConfig("HttpServlet", "appContext", Mockito.mock(CallbackHandler.class));
        serverAuthConfig.getAuthContext("autocontextid", new Subject(), null);
    }
}
