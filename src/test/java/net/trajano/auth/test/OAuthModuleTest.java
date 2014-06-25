package net.trajano.auth.test;

import java.util.HashMap;
import java.util.Map;

import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;

import org.junit.Test;

/**
 * Tests the OAuthModule.
 */
public class OAuthModuleTest {

    /**
     * Tests getting the configuration from Google.
     *
     * @throws Exception
     */
    @Test
    public void testGoogleOpenIdConfiguration() throws Exception {
        final Map<String, String> options = new HashMap<>();
        options.put(OAuthModule.CLIENT_ID_KEY, "clientID");
        options.put(OAuthModule.CLIENT_SECRET_KEY, "clientSecret");
        options.put(OpenIDConnectAuthModule.ISSUER_URI_KEY,
                "https://accounts.google.com/");

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        module.initialize(null, null, null, options);
    }

    /**
     * Tests getting the configuration from Salesforce.
     *
     * @throws Exception
     */
    @Test
    public void testSalesforceOpenIdConfiguration() throws Exception {
        final Map<String, String> options = new HashMap<>();
        options.put(OAuthModule.CLIENT_ID_KEY, "clientID");
        options.put(OAuthModule.CLIENT_SECRET_KEY, "clientSecret");
        options.put(OpenIDConnectAuthModule.ISSUER_URI_KEY,
                "https://login.salesforce.com");

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        module.initialize(null, null, null, options);
    }
}