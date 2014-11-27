package net.trajano.auth;

import static net.trajano.auth.internal.OAuthParameters.CLIENT_ID;
import static net.trajano.auth.internal.OAuthParameters.CODE;
import static net.trajano.auth.internal.OAuthParameters.GRANT_TYPE;
import static net.trajano.auth.internal.OAuthParameters.REDIRECT_URI;

import java.io.IOException;
import java.util.Map;

import javax.json.Json;
import javax.security.auth.message.AuthException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import net.trajano.auth.internal.OAuthToken;
import net.trajano.auth.internal.OpenIDProviderConfiguration;

/**
 * Google Server Auth Module. Uses Google services to do OAuth 2.0 Login. It
 * extends {@link OAuthModule} to get the configuration from the module rather
 * from Google.
 *
 * @author Archimedes Trajano
 */
public class GoogleAuthModule extends OAuthModule {

    /**
     * Build the OpenID config from META-INF/google/config.json.
     *
     * @param req
     *            ignored
     * @param restClient
     *            REST client
     * @param options
     *            ignored
     * @return OpenID provider configuration
     */
    @Override
    protected OpenIDProviderConfiguration getOpenIDProviderConfig(final HttpServletRequest req,
            final Client restClient,
            final Map<String, String> options) throws AuthException {

        return new OpenIDProviderConfiguration(Json.createReader(Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("META-INF/google-config.json"))
                .readObject());
    }

    /**
     * Only does the passing of the authentication token via the POST parameters
     * and does not try to do it via the authorization headers. {@inheritDoc}
     */
    @Override
    protected OAuthToken getToken(final HttpServletRequest req,
            final OpenIDProviderConfiguration oidProviderConfig) throws IOException {

        final MultivaluedMap<String, String> requestData = new MultivaluedHashMap<>();
        requestData.putSingle(CODE, req.getParameter("code"));
        requestData.putSingle(GRANT_TYPE, "authorization_code");
        requestData.putSingle(REDIRECT_URI, getRedirectionEndpointUri(req).toASCIIString());
        requestData.putSingle(CLIENT_ID, getClientId());
        requestData.putSingle(CLIENT_SECRET_KEY, getClientSecret());
        final OAuthToken authorizationTokenResponse = getRestClient().target(oidProviderConfig.getTokenEndpoint())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.form(requestData), OAuthToken.class);
        return authorizationTokenResponse;
    }
}
