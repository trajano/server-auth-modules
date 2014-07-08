package net.trajano.auth;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * HTTP header server auth module. This can be used with SiteMinder type data.
 *
 * @author Archimedes Trajano
 *
 */
public class HttpHeaderAuthModule implements ServerAuthModule {

    /**
     * Group Header option key.
     */
    private static final String GROUP_HEADER_KEY = "group_header";

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

    /**
     * Supported message types. For our case we only need to deal with HTTP
     * servlet request and responses. On Java EE 7 this will handle WebSockets
     * as well.
     */
    private static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[] {
            HttpServletRequest.class, HttpServletResponse.class };

    /**
     * User Name Header option key.
     */
    private static final String USERNAME_HEADER_KEY = "username_header";

    static {
        LOG = Logger.getLogger("net.trajano.auth.httpheadersam", MESSAGES);
        R = ResourceBundle.getBundle(MESSAGES);
    }

    /**
     * Group header option.
     */
    private String groupHeader;

    /**
     * Callback handler that is passed in initialize by the container. This
     * processes the callbacks which are objects that populate the "subject".
     */
    private CallbackHandler handler;

    /**
     * User name header option.
     */
    private String userNameHeader;

    /**
     * Does nothing.
     *
     * @param messageInfo
     *            message info
     * @param subject
     *            subject
     */
    @Override
    public void cleanSubject(final MessageInfo messageInfo,
            final Subject subject) throws AuthException {
    }

    /**
     * {@inheritDoc}
     * <p>
     * The array it returns contains immutable data so it is secure and faster
     * to return the internal array.
     * </p>
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Class[] getSupportedMessageTypes() {
        return SUPPORTED_MESSAGE_TYPES; // NOPMD
    }

    /**
     * Builds a list of groups from the request. If not defined, then "users" is
     * returned.
     *
     * @param req
     *            servlet request.
     * @return array of groups.
     */
    private String[] groups(final HttpServletRequest req) {
        if (groupHeader == null) {
            return new String[] { "users" };
        }
        final List<String> groupList = new LinkedList<>();
        final Enumeration<String> groupHeaders = req.getHeaders(groupHeader);
        while (groupHeaders.hasMoreElements()) {
            for (final String groupName : groupHeaders.nextElement().split(",")) {
                groupList.add(groupName.trim());
            }
        }
        return groupList.toArray(new String[0]);
    }

    /**
     * {@inheritDoc}
     *
     * @param requestPolicy
     *            request policy, ignored
     * @param responsePolicy
     *            response policy, ignored
     * @param h
     *            callback handler
     * @param options
     *            options
     */
    @Override
    public void initialize(final MessagePolicy requestPolicy,
            final MessagePolicy responsePolicy, final CallbackHandler h,
            @SuppressWarnings("rawtypes") final Map options)
            throws AuthException {
        handler = h;

        userNameHeader = (String) options.get(USERNAME_HEADER_KEY);
        if (userNameHeader == null) {
            LOG.log(Level.SEVERE, "missingOption", USERNAME_HEADER_KEY);
            throw new AuthException(MessageFormat.format(
                    R.getString("missingOption"), USERNAME_HEADER_KEY));
        }
        groupHeader = (String) options.get(GROUP_HEADER_KEY);
    }

    /**
     * Return {@link AuthStatus#SEND_SUCCESS}.
     *
     * @param messageInfo
     *            contains the request and response messages. At this point the
     *            response message is already committed so nothing can be
     *            changed.
     * @param subject
     *            subject.
     * @return {@link AuthStatus#SEND_SUCCESS}
     */
    @Override
    public AuthStatus secureResponse(final MessageInfo messageInfo,
            final Subject subject) throws AuthException {
        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo,
            final Subject client, final Subject serviceSubject)
            throws AuthException {
        final HttpServletRequest req = (HttpServletRequest) messageInfo
                .getRequestMessage();
        try {
            if (!req.isSecure()) {
                return AuthStatus.FAILURE;
            }
            final String userName = req.getHeader(userNameHeader);
            if (userName == null) {
                return AuthStatus.FAILURE;
            }

            handler.handle(new Callback[] {
                    new CallerPrincipalCallback(client, userName),
                    new GroupPrincipalCallback(client, groups(req)) });
            return AuthStatus.SUCCESS;
        } catch (final IOException | UnsupportedCallbackException e) {
            throw new AuthException(e.getMessage());
        }
    }

}
