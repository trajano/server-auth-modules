package net.trajano.auth.filter.internal;

import java.io.Serializable;
import java.security.Principal;

/**
 * Simple String based principal.
 */
public class BasicPrincipal implements Principal, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -4296011711486060357L;
    /**
     * Name.
     */
    private final String name;

    /**
     * Constructs the principal.
     *
     * @param name
     *            name
     */
    public BasicPrincipal(final String name) {
        this.name = name;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return name;
    }

}
