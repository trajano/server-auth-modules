package net.trajano.auth.test;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;

import org.junit.Test;

public class UnsecureJaxRsClientIT {
    /**
     * Google should always have a valid SSL. Test this.
     */
    @Test
    public void testHttpsConnectionToGoogle() throws Exception {
        final OAuthModule module = new OpenIDConnectAuthModule();
        final Client client = module.buildUnsecureRestClient();
        client.target("https://accounts.google.com/.well-known/openid-configuration")
        .request()
        .get();
    }

    /**
     * This is an invalid certificate referenced by
     * https://onlinessl.netlock.hu/en/test-center/invalid-ssl-certificate.html
     *
     * @throws Exception
     */
    @Test
    public void testInvalidCertificate() throws Exception {
        final OAuthModule module = new OpenIDConnectAuthModule();
        final Client client = module.buildUnsecureRestClient();
        client.target("https://tv.eurosport.com/")
        .request()
        .get();
    }

    /**
     * Failure test. This is an invalid certificate referenced by
     * https://onlinessl.netlock.hu/en/test-center/invalid-ssl-certificate.html
     *
     * @throws Exception
     */
    @Test(expected = ProcessingException.class)
    public void testInvalidCertificateFailure() throws Exception {
        final Client client = ClientBuilder.newClient();
        client.target("https://tv.eurosport.com/")
        .request()
        .get();
    }
}
