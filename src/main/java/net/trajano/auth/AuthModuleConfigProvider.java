package net.trajano.auth;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.module.ClientAuthModule;
import javax.security.auth.message.module.ServerAuthModule;

import net.trajano.auth.internal.ClientAuthModuleAuthConfig;
import net.trajano.auth.internal.ServerAuthModuleAuthConfig;

/**
 * This is used to provide the server auth module on the application rather than
 * being globally configured in a container. The following is an example of
 * registering the provider in a {@link javax.servlet.ServletContextListener}.
 *
 * <pre>
 *
 * 
 * &#064;WebListener
 * public class Initializer implements ServletContextListener {
 * 
 *     &#064;Override
 *     public void contextInitialized(final ServletContextEvent sce) {
 * 
 *         Map&lt;String, String&gt; options = new HashMap&lt;&gt;();
 *         options.put(AuthModuleConfigProvider.SERVER_AUTH_MODULE_CLASS, OpenIDConnectAuthModule.class.getName());
 *         AuthConfigFactory.getFactory()
 *                 .registerConfigProvider(AuthModuleConfigProvider.class.getName(), options, &quot;HttpServlet&quot;, null, null);
 *     }
 * }
 * </pre>
 */
public class AuthModuleConfigProvider implements AuthConfigProvider {

    /**
     * Client auth module class option key.
     */
    public static final String CLIENT_AUTH_MODULE_CLASS = ClientAuthModule.class.getName();

    /**
     * Server auth module class option key.
     */
    public static final String SERVER_AUTH_MODULE_CLASS = ServerAuthModule.class.getName();

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
    public AuthModuleConfigProvider(final Map<String, String> options, final AuthConfigFactory authConfigFactory) {

        this.authConfigFactory = authConfigFactory;
        this.options = options;
    }

    @Override
    public ClientAuthConfig getClientAuthConfig(final String layer,
            final String appContext,
            final CallbackHandler handler) throws AuthException {

        if (options.containsKey(CLIENT_AUTH_MODULE_CLASS)) {
            return new ClientAuthModuleAuthConfig(options, layer, appContext, handler);
        }
        return null;
    }

    @Override
    public ServerAuthConfig getServerAuthConfig(final String layer,
            final String appContext,
            final CallbackHandler handler) throws AuthException {

        if (options.containsKey(SERVER_AUTH_MODULE_CLASS)) {
            return new ServerAuthModuleAuthConfig(options, layer, appContext, handler);
        }
        return null;
    }

    /**
     * Does nothing.
     */
    @Override
    public void refresh() {

        // does nothing
    }

}
