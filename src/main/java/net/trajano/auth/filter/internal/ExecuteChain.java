package net.trajano.auth.filter.internal;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Action that will perform the execution of a servlet filter chain as a
 * privileged action.
 */
public class ExecuteChain implements PrivilegedExceptionAction<Object> {
    /**
     * Filter chain.
     */
    private transient final FilterChain chain;
    /**
     * Request.
     */
    private transient final HttpServletRequest request;
    /**
     * Response.
     */
    private transient final HttpServletResponse response;

    /**
     * Constructs the action.
     *
     * @param chain
     *            filter chain
     * @param request
     *            servlet request
     * @param response
     *            servlet response
     */
    public ExecuteChain(final FilterChain chain, final HttpServletRequest request, final HttpServletResponse response) {
        this.chain = chain;
        this.request = request;
        this.response = response;
    }

    /**
     * Executes the filter chain.
     *
     * @return <code>null</code> as a return type is required.
     */
    @Override
    public Object run() throws ServletException, IOException {
        chain.doFilter(request, response);
        return null;
    }
}
