package net.trajano.auth.filter;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.MessagePolicy.TargetPolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.auth.filter.internal.ExecuteChain;
import net.trajano.auth.filter.internal.HttpServletRequestResponseMessageInfo;
import net.trajano.auth.filter.internal.JaspicFilterCallbackHandler;
import net.trajano.auth.filter.internal.UserInjectedServletRequest;

/**
 * This is a filter that calls upon the JASPIC ServerAuthModules. This is used
 * if JASPIC deployment is not an option because the servers are more locked
 * down.
 */
public class JaspicFilter implements Filter {

    /**
     * Server auth module class.
     */
    private static final String SERVER_AUTH_MODULE_CLASS = "server_auth_module_class";
    /**
     * Options.
     */
    private Map<String, String> options;
    /**
     * {@link ServerAuthModule} class.
     */
    private Class<? extends ServerAuthModule> serverAuthModuleClass;

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        try {
            final ServerAuthModule serverAuthModule = serverAuthModuleClass.newInstance();
            final JaspicFilterCallbackHandler handler = new JaspicFilterCallbackHandler();
            serverAuthModule.initialize(new MessagePolicy(new TargetPolicy[0], true), null, handler, options);
            @SuppressWarnings("rawtypes")
            final List<Class> supportedTypes = Arrays.asList(serverAuthModule.getSupportedMessageTypes());
            if (!supportedTypes.contains(HttpServletRequest.class) || !supportedTypes.contains(HttpServletResponse.class)) {
                throw new ServletException("The server auth module " + serverAuthModuleClass + " must support HttpServletRequest and HttpServletResponse message types.");
            }
            final HttpServletRequestResponseMessageInfo messageInfo = new HttpServletRequestResponseMessageInfo();
            messageInfo.setRequestMessage(request);
            messageInfo.setResponseMessage(response);
            final Subject clientSubject = new Subject();
            final AuthStatus authStatus = serverAuthModule.validateRequest(messageInfo, clientSubject, null);
            if (authStatus == AuthStatus.FAILURE) {
                throw new ServletException("Auth Failure");
            } else if (authStatus == AuthStatus.SUCCESS) {
                try {
                    final UserInjectedServletRequest wrappedRequest = new UserInjectedServletRequest((HttpServletRequest) request, handler.getUserPrincipal());
                    Subject.doAs(clientSubject, new ExecuteChain(chain, wrappedRequest, (HttpServletResponse) response));
                } catch (final PrivilegedActionException e) {
                    if (e.getCause() instanceof IOException) {
                        throw (IOException) e.getCause();
                    } else if (e.getCause() instanceof ServletException) {
                        throw (ServletException) e.getCause();
                    } else {
                        throw e;
                    }
                }
            } else if (authStatus == AuthStatus.SEND_FAILURE) {
                response.flushBuffer();
            } else if (authStatus == AuthStatus.SEND_SUCCESS) {
                response.flushBuffer();
            }
            serverAuthModule.cleanSubject(messageInfo, clientSubject);
        } catch (final AuthException | InstantiationException | IllegalAccessException | PrivilegedActionException e) {
            throw new ServletException(e);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        try {
            serverAuthModuleClass = (Class<? extends ServerAuthModule>) Class.forName(filterConfig.getInitParameter(SERVER_AUTH_MODULE_CLASS));
        } catch (final ClassNotFoundException e) {
            throw new ServletException(e);
        }
        final String contextPath = filterConfig.getServletContext()
                .getContextPath();
        options = new HashMap<String, String>();
        final Enumeration<String> initParameterNames = filterConfig.getInitParameterNames();
        while (initParameterNames.hasMoreElements()) {
            final String name = initParameterNames.nextElement();
            if (name == SERVER_AUTH_MODULE_CLASS) {
                continue;
            }
            options.put(name, filterConfig.getInitParameter(name)
                    .replaceAll("\\$context", contextPath));
        }
    }
}
