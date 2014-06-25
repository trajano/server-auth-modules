package net.trajano.auth;

import java.util.Map;

import javax.json.Json;
import javax.security.auth.message.AuthException;

import net.trajano.auth.internal.OpenIDProviderConfiguration;

/**
 * Google Server Auth Module. Uses Google services to do OAuth 2.0 Login. It
 * extends {@link OAuthModule} to get the configuration from the
 * module rather from Google.
 *
 * @author Archimedes Trajano
 *
 */
public class GoogleAuthModule extends OAuthModule {

    /**
     * Build the OpenID config from META-INF/google/config.json.
     *
     * @param options
     *            ignored
     * @return OpenID provider configuration
     */
    @Override
    protected OpenIDProviderConfiguration getOpenIDProviderConfig(
            final Map<String, String> options) throws AuthException {
        return new OpenIDProviderConfiguration(Json.createReader(
                Thread.currentThread().getContextClassLoader()
                .getResourceAsStream("META-INF/google-config.json"))
                .readObject());
    }
}
