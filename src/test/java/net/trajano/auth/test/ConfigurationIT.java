package net.trajano.auth.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.json.JsonObject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import net.trajano.auth.internal.JsonWebKeySet;
import net.trajano.auth.internal.OpenIDProviderConfiguration;

import org.junit.Test;

/**
 * Tests the configuration processing.
 */
public class ConfigurationIT {

    /**
     * Tests getting the configuration from Google.
     *
     * @throws Exception
     */
    @Test
    public void testGoogleOpenIdConfiguration() throws Exception {
        ClientBuilder.newClient()
        .target("https://accounts.google.com/.well-known/openid-configuration")
        .request()
                .get(OpenIDProviderConfiguration.class);
    }

    /**
     * Tests retrival of JWK keys.
     *
     * @throws Exception
     */
    @Test
    public void testJwkRetrieval() throws Exception {
        final Client restClient = ClientBuilder.newClient();
        final OpenIDProviderConfiguration openIdProviderConfiguration = restClient.target("https://accounts.google.com/.well-known/openid-configuration")
                .request()
                .get(OpenIDProviderConfiguration.class);
        final JsonWebKeySet webKeys = new JsonWebKeySet(restClient.target(openIdProviderConfiguration.getJwksUri())
                .request()
                .get(JsonObject.class));
        assertNotNull(webKeys);
    }

    /**
     * Tests getting the configuration from Salesforce.
     *
     * @throws Exception
     */
    @Test
    public void testSalesforceOpenIdConfiguration() throws Exception {
        final Client restClient = ClientBuilder.newClient();
        final OpenIDProviderConfiguration config = restClient.target("https://login.salesforce.com/.well-known/openid-configuration")
                .request()
                .get(OpenIDProviderConfiguration.class);
        assertEquals("https://login.salesforce.com", config.getIssuer());
    }
}
