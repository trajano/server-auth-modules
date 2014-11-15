package net.trajano.auth.filter.internal;

import java.security.Principal;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * A principal with the remote user data injected in.
 */
public class UserInjectedServletRequest extends HttpServletRequestWrapper {
    /**
     * Flag to indicate that the user is logged in.
     */
    private boolean loggedIn = true;
    /**
     * Remote user.
     */
    private final String remoteUser;
    /**
     * User principal to send.
     */
    private final Principal userPrincipal;

    /**
     * Wraps the request.
     *
     * @param req
     *            request to wrap
     * @param userPrincipal
     *            user principal containing the authenticated user
     */
    public UserInjectedServletRequest(final HttpServletRequest req, final Principal userPrincipal) {
        super(req);
        remoteUser = userPrincipal.getName();
        this.userPrincipal = userPrincipal;
    }

    /**
     * Sends "BASIC" when authenticated, <code>null</code> otherwise.
     *
     * @return "BASIC" or <code>null</code>.
     */
    @Override
    public String getAuthType() {
        return loggedIn ? "BASIC" : null;
    }

    /**
     * {@inheritDoc}
     *
     * @return remote user if authenticated, <code>null</code> otherwise.
     */
    @Override
    public String getRemoteUser() {
        return loggedIn ? remoteUser : null;
    }

    /**
     * {@inheritDoc}
     *
     * @return the user principal if logged in. <code>null</code> otherwise.
     */
    @Override
    public Principal getUserPrincipal() {
        return loggedIn ? userPrincipal : null;
    }

    @Override
    public void logout() throws ServletException {
        loggedIn = false;
    }

}
