package net.trajano.auth.filter.internal;

import java.io.IOException;
import java.security.Principal;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;

/**
 * JASPIC filter callback handler.
 */
public class JaspicFilterCallbackHandler implements CallbackHandler {
    /**
     * User principal. This is set by the {@link CallerPrincipalCallback}.
     */
    private Principal userPrincipal;

    public Principal getUserPrincipal() {
        return userPrincipal;
    }

    @Override
    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        for (final Callback callback : callbacks) {
            if (callback instanceof CallerPrincipalCallback) {
                final CallerPrincipalCallback cb = (CallerPrincipalCallback) callback;
                if (cb.getPrincipal() != null) {
                    cb.getSubject()
                            .getPrincipals()
                            .add(cb.getPrincipal());
                    userPrincipal = cb.getPrincipal();
                } else if (cb.getName() != null) {
                    final Principal p = new BasicPrincipal(cb.getName());
                    cb.getSubject()
                            .getPrincipals()
                            .add(p);
                    userPrincipal = p;
                }
            } else if (callback instanceof GroupPrincipalCallback) {
                final GroupPrincipalCallback cb = (GroupPrincipalCallback) callback;
                for (final String group : cb.getGroups()) {
                    final Principal p = new BasicPrincipal(group);
                    cb.getSubject()
                            .getPrincipals()
                            .add(p);
                }
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }
}
