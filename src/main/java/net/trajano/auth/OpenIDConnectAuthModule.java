package net.trajano.auth;

import java.net.URI;
import java.text.MessageFormat;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.message.AuthException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.MediaType;

import net.trajano.auth.internal.OpenIDProviderConfiguration;

/**
 * OpenID Connect Server Auth Module. This uses OpenID Connect Discovery to
 * configure the OAuth 2.0 Login.
 *
 * @author Archimedes Trajano
 */
public class OpenIDConnectAuthModule extends OAuthModule {

    /**
     * Issuer URI option key.
     */
    public static final String ISSUER_URI_KEY = "issuer_uri";

    /**
     * Logger.
     */
    private static final Logger LOG;

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    /**
     * Resource bundle.
     */
    private static final ResourceBundle R;

    static {
        LOG = Logger.getLogger("net.trajano.auth.openidsam", MESSAGES);
        R = ResourceBundle.getBundle(MESSAGES);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected OpenIDProviderConfiguration getOpenIDProviderConfig(final HttpServletRequest req,
            final Client restClient,
            final Map<String, String> options) throws AuthException {

        final String issuerUri = options.get(ISSUER_URI_KEY);
        if (issuerUri == null) {
            LOG.log(Level.SEVERE, "missingOption", ISSUER_URI_KEY);
            throw new AuthException(MessageFormat.format(R.getString("missingOption"), ISSUER_URI_KEY));
        }
        return restClient.target(URI.create(issuerUri)
                .resolve("/.well-known/openid-configuration"))
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(OpenIDProviderConfiguration.class);
    }

}
