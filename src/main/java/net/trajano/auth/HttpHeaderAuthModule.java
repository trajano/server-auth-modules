package net.trajano.auth;

import java.io.IOException;
import java.net.HttpURLConnection;
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
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * HTTP header server auth module. This can be used with SiteMinder type data.
 *
 * @author Archimedes Trajano
 */
public class HttpHeaderAuthModule implements ServerAuthModule, ServerAuthContext {

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
     * User Name Header option key.
     */
    public static final String USERNAME_HEADER_KEY = "username_header";

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
     * Mandatory flag.
     */
    private boolean mandatory;

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
    public void cleanSubject(final MessageInfo messageInfo, final Subject subject) throws AuthException {
        // Does nothing.
    }

    /**
     * <p>
     * Supported message types. For our case we only need to deal with HTTP
     * servlet request and responses. On Java EE 7 this will handle WebSockets
     * as well.
     * </p>
     * <p>
     * This creates a new array for security at the expense of performance.
     * </p>
     *
     * @return {@link HttpServletRequest} and {@link HttpServletResponse}
     *         classes.
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Class[] getSupportedMessageTypes() {
        return new Class<?>[] { HttpServletRequest.class, HttpServletResponse.class };
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
            for (final String groupName : groupHeaders.nextElement()
                    .split(",")) {
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
    public void initialize(final MessagePolicy requestPolicy, final MessagePolicy responsePolicy, final CallbackHandler h, @SuppressWarnings("rawtypes") final Map options) throws AuthException {
        handler = h;
        mandatory = requestPolicy.isMandatory();
        userNameHeader = (String) options.get(USERNAME_HEADER_KEY);
        if (userNameHeader == null) {
            LOG.log(Level.SEVERE, "missingOption", USERNAME_HEADER_KEY);
            throw new AuthException(MessageFormat.format(R.getString("missingOption"), USERNAME_HEADER_KEY));
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
    public AuthStatus secureResponse(final MessageInfo messageInfo, final Subject subject) throws AuthException {
        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo, final Subject client, final Subject serviceSubject) throws AuthException {
        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();
        try {
            if (!mandatory && !req.isSecure()) {
                return AuthStatus.SUCCESS;
            }
            if (!req.isSecure()) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, R.getString("SSLReq"));
                return AuthStatus.SEND_FAILURE;
            }
            final String userName = req.getHeader(userNameHeader);
            if (userName == null && mandatory) {
                return AuthStatus.FAILURE;
            } else if (userName == null && !mandatory) {
                return AuthStatus.SUCCESS;
            }

            handler.handle(new Callback[] { new CallerPrincipalCallback(client, userName), new GroupPrincipalCallback(client, groups(req)) });
            return AuthStatus.SUCCESS;
        } catch (final IOException | UnsupportedCallbackException e) {
            LOG.throwing(this.getClass()
                    .getName(), "validateRequest", e);
            throw new AuthException(e.getMessage());
        }
    }

}
