package net.trajano.auth.internal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

import net.trajano.auth.OpenIDConnectAuthModule;

/**
 * A {@link ServerAuthConfig} specifically for {@link OpenIDConnectAuthModule}.
 */
public class OpenIDConnectServerAuthConfig implements ServerAuthConfig {

    /**
     * Application context.
     */
    private final String appContext;

    /**
     * Callback handler.
     */
    private final CallbackHandler handler;

    /**
     * Layer. Usually HttpServlet or SOAPMessage.
     */
    private final String layer;

    /**
     * Setup options.
     */
    private final Map<String, String> options;

    /**
     * @param options
     *            options
     * @param layer
     *            layer
     * @param appContext
     *            application context
     * @param handler
     *            handler
     */
    public OpenIDConnectServerAuthConfig(final Map<String, String> options, final String layer, final String appContext, final CallbackHandler handler) {

        this.appContext = appContext;
        this.layer = layer;
        this.options = options;
        this.handler = handler;
    }

    @Override
    public String getAppContext() {

        return appContext;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    public ServerAuthContext getAuthContext(final String authContextID,
            final Subject serviceSubject,
            final Map properties) throws AuthException {

        final Map augmentedOptions;
        if (properties == null) {
            augmentedOptions = options;
        } else {
            augmentedOptions = new ConcurrentHashMap(options);
            augmentedOptions.putAll(properties);
        }

        final OpenIDConnectAuthModule module = new OpenIDConnectAuthModule();
        if (authContextID == null) {
            module.initialize(new MessagePolicy(new TargetPolicy[0], false), new MessagePolicy(new TargetPolicy[0], false), handler, augmentedOptions);
        } else {
            module.initialize(new MessagePolicy(new TargetPolicy[0], true), new MessagePolicy(new TargetPolicy[0], true), handler, augmentedOptions);
        }

        return module;
    }

    @Override
    public String getAuthContextID(final MessageInfo messageInfo) {

        final Object isMandatory = messageInfo.getMap()
                .get("javax.security.auth.message.MessagePolicy.isMandatory");
        if (isMandatory != null && isMandatory instanceof String && Boolean.valueOf((String) isMandatory)) {
            return messageInfo.toString();
        }
        return null;

    }

    @Override
    public String getMessageLayer() {

        return layer;
    }

    @Override
    public boolean isProtected() {

        return true;
    }

    @Override
    public void refresh() {

        // does nothing
    }

}
