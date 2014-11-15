package net.trajano.auth.internal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;

/**
 * Common methods for ServerAuthConfig and ClientAuthConfig.
 */
public abstract class AbstractAuthModuleAuthConfig {
    /**
     * <p>
     * The {@link MessageInfo} map must contain this key and its associated
     * value, if and only if authentication is required to perform the resource
     * access corresponding to the HttpServletRequest to which the
     * ServerAuthContext will be applied. Authentication is required if use of
     * the HTTP method of the HttpServletRequest at the resource identified by
     * the HttpServletRequest is covered by a Servlet authconstraint, or in a
     * JSR 115 compatible runtime, if the corresponding WebResourcePermission is
     * NOT granted to an unauthenticated caller. In a JSR 115 compatible
     * runtime, the corresponding WebResourcePermission may be constructed
     * directly from the HttpServletRequest as follows:
     * </p>
     *
     * <pre>
     * public WebResourcePermission(HttpServletRequest request);
     * </pre>
     * <p>
     * The authentication context configuration system must use the value of
     * this property to establish the corresponding value within the
     * requestPolicy passed to the authentication modules of the
     * {@link javax.security.auth.message.config.ServerAuthContext} acquired to
     * process the {@link MessageInfo}.
     * </p>
     */
    private static final String JAVAX_SECURITY_AUTH_MESSAGE_MESSAGE_POLICY_IS_MANDATORY = "javax.security.auth.message.MessagePolicy.isMandatory";
    /**
     * Mandatory message policy.
     */
    protected static final MessagePolicy MANDATORY = new MessagePolicy(new TargetPolicy[0], true);
    /**
     * Non-mandatory message policy.
     */
    protected static final MessagePolicy NON_MANDATORY = new MessagePolicy(new TargetPolicy[0], false);
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
    public AbstractAuthModuleAuthConfig(final Map<String, String> options, final String layer, final String appContext, final CallbackHandler handler) {
        this.appContext = appContext;
        this.layer = layer;
        this.options = options;
        this.handler = handler;
    }

    /**
     * Augments the properties with additional properties.
     *
     * @param properties
     *            properties to augment with.
     * @return augmented properties
     */
    @SuppressWarnings("unchecked")
    protected Map<?, ?> augmentProperties(@SuppressWarnings("rawtypes") final Map properties) {
        if (properties == null) {
            return options;
        }
        final ConcurrentMap<?, ?> augmentedOptions = new ConcurrentHashMap<>(options);
        augmentedOptions.putAll(properties);
        return augmentedOptions;

    }

    public String getAppContext() {
        return appContext;
    }

    /**
     * Checks for the presence of
     * {@value #JAVAX_SECURITY_AUTH_MESSAGE_MESSAGE_POLICY_IS_MANDATORY} in the
     * map.
     *
     * @param messageInfo
     *            contains the message request, response and some system
     *            populated map.
     * @return the string representation of the {@link MessageInfo} if it is
     *         mandatory, <code>null</code> otherwise.
     */
    public String getAuthContextID(final MessageInfo messageInfo) {
        final Object isMandatory = messageInfo.getMap()
                .get(JAVAX_SECURITY_AUTH_MESSAGE_MESSAGE_POLICY_IS_MANDATORY);
        if (isMandatory != null && isMandatory instanceof String && Boolean.valueOf((String) isMandatory)) {
            return messageInfo.toString();
        }
        return null;
    }

    protected CallbackHandler getHandler() {
        return handler;
    }

    public String getMessageLayer() {
        return layer;
    }

    public boolean isProtected() {
        return true;
    }

    /**
     * Does nothing as the module does not accept changes at runtime.
     */
    public void refresh() {
    }

}
