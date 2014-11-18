package net.trajano.auth;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;

import net.trajano.auth.internal.OpenIDConnectServerAuthConfig;

/**
 * This is used to provide the server auth module on the application rather than
 * being globally configured in a container.
 */
public class OpenIDConnectAuthModuleConfigProvider implements AuthConfigProvider {

    /**
     * {@link AuthConfigFactory} passed in through the constructor. This is not
     * being used anywhere at the moment.
     */
    @SuppressWarnings("unused")
    private final AuthConfigFactory authConfigFactory;

    /**
     * Options.
     */
    private final Map<String, String> options;

    /**
     * This is called by
     * {@link AuthConfigFactory#registerConfigProvider(String, Map, String, String, String)}
     * when registering the provider.
     *
     * @param options
     *            options to pass to the modules and the name of the module
     *            classes
     * @param authConfigFactory
     *            configuration factory
     */
    public OpenIDConnectAuthModuleConfigProvider(final Map<String, String> options, final AuthConfigFactory authConfigFactory) {

        this.authConfigFactory = authConfigFactory;
        this.options = options;
    }

    @Override
    public ClientAuthConfig getClientAuthConfig(final String layer,
            final String appContext,
            final CallbackHandler handler) throws AuthException {

        return null;
    }

    @Override
    public ServerAuthConfig getServerAuthConfig(final String layer,
            final String appContext,
            final CallbackHandler handler) throws AuthException {

        return new OpenIDConnectServerAuthConfig(options, layer, appContext, handler);
    }

    /**
     * Does nothing.
     */
    @Override
    public void refresh() {

        // Does nothing
    }

}
