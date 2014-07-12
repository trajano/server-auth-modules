package net.trajano.auth;

import static net.trajano.auth.internal.OAuthParameters.CLIENT_ID;
import static net.trajano.auth.internal.OAuthParameters.CLIENT_SECRET;
import static net.trajano.auth.internal.OAuthParameters.CODE;
import static net.trajano.auth.internal.OAuthParameters.GRANT_TYPE;
import static net.trajano.auth.internal.OAuthParameters.REDIRECT_URI;
import static net.trajano.auth.internal.OAuthParameters.RESPONSE_TYPE;
import static net.trajano.auth.internal.OAuthParameters.SCOPE;
import static net.trajano.auth.internal.OAuthParameters.STATE;
import static net.trajano.auth.internal.Utils.isGetRequest;
import static net.trajano.auth.internal.Utils.isHeadRequest;
import static net.trajano.auth.internal.Utils.isIdempotentRequest;
import static net.trajano.auth.internal.Utils.isNullOrEmpty;
import static net.trajano.auth.internal.Utils.validateIdToken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.json.Json;
import javax.json.JsonObject;
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
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.auth.internal.Base64;
import net.trajano.auth.internal.JsonWebKeySet;
import net.trajano.auth.internal.OAuthToken;
import net.trajano.auth.internal.OpenIDProviderConfiguration;
import net.trajano.auth.internal.TokenCookie;
import net.trajano.auth.internal.Utils;

/**
 * OAuth 2.0 server authentication module. This is an implementation of the <a
 * href="http://tools.ietf.org/html/rfc6749">OAuth 2.0 authentication
 * framework</a>. This assumes no HttpSessions which makes it useful for RESTful
 * applications and uses the OAuth token to manage the authentication state.
 *
 * The e-mail addresses are not requested.
 *
 * @author Archimedes Trajano
 *
 */
public abstract class OAuthModule implements ServerAuthModule {
    /**
     * Client ID option key and JSON key.
     */
    public static final String CLIENT_ID_KEY = "client_id";

    /**
     * Client secret option key and JSON key.
     */
    public static final String CLIENT_SECRET_KEY = "client_secret";

    /**
     * Cookie context option key. The value is optional.
     */
    public static final String COOKIE_CONTEXT_KEY = "cookie_context";

    /**
     * https prefix.
     */
    private static final String HTTPS_PREFIX = "https://";

    /**
     * Logger.
     */
    private static final Logger LOG;

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    /**
     * Age cookie name. The value of this cookie is "1" and will expire based on
     * the max age of the token.
     */
    public static final String NET_TRAJANO_AUTH_AGE = "net.trajano.auth.age";

    /**
     * ID token cookie name. This one expires when the browser closes.
     */
    public static final String NET_TRAJANO_AUTH_ID = "net.trajano.auth.id";

    /**
     * User info attribute name.
     */
    private static final String NET_TRAJANO_AUTH_USERINFO = "net.trajano.auth.userinfo";

    /**
     * Resource bundle.
     */
    private static final ResourceBundle R;

    /**
     * Redirection endpoint URI key. The value is optional and defaults to the
     * context root of the application.
     */
    public static final String REDIRECTION_ENDPOINT_URI_KEY = "redirection_endpoint";

    /**
     * Scope option key. The value is optional and defaults to "openid"
     */
    public static final String SCOPE_KEY = "scope";

    /**
     * Token URI key. The value is optional and if not specified, the token
     * request functionality will not be available.
     */
    public static final String TOKEN_URI_KEY = "token_uri";

    /**
     * User Info URI key. The value is optional and if not specified, the
     * userinfo request functionality will not be available.
     */
    public static final String USERINFO_URI_KEY = "userinfo_uri";

    static {
        LOG = Logger.getLogger("net.trajano.auth.oauthsam", MESSAGES);
        R = ResourceBundle.getBundle(MESSAGES);
    }

    /**
     * Client ID. This is set through "client.id" option.
     */
    private String clientId;

    /**
     * Client secret. This is set through "client.secret" option.
     */
    private String clientSecret;

    /**
     * Cookie context path. Set through through "cookie.context" option. This is
     * optional.
     */
    private String cookieContext;

    /**
     * Callback handler.
     */
    private CallbackHandler handler;

    /**
     * Options for the module.
     */
    private Map<String, String> moduleOptions;

    /**
     * Redirection endpoint URI. This is set through "redirection_endpoint"
     * option. This must start with a forward slash. This value is optional.
     */
    private String redirectionEndpointUri;

    /**
     * Scope.
     */
    private String scope;

    /**
     * Token URI. This is set through "token_uri" option. This must start with a
     * forward slash. This value is optional. The calling the token URI will
     * return the contents of the JWT token object to the user. Make sure that
     * this is intended before setting the value.
     */
    private String tokenUri;

    /**
     * User info URI. This is set through "userinfo_uri" option. This must start
     * with a forward slash. This value is optional. The calling the user info
     * URI will return the contents of the user info object to the user. Make
     * sure that this is intended before setting the value.
     */
    private String userInfoUri;

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
     * Handles "GET" requests that have a valid token. It handles the special
     * case then token URI or the user info URI is requested.
     *
     * @param req
     *            request
     * @param resp
     *            response
     * @param tokenCookie
     *            token cookie
     * @param requestCookieContext
     *            request cookie context
     * @param subject
     *            subject
     * @return {@link AuthStatus#SEND_SUCCESS} if processed by the module,
     *         {@link AuthStatus#SUCCESS} otherwise.
     * @throws IOException
     */
    private AuthStatus doGetWithToken(final HttpServletRequest req,
            final HttpServletResponse resp, final TokenCookie tokenCookie,
            final String requestCookieContext, final Subject subject)
                    throws IOException {
        if (req.getRequestURI().equals(tokenUri)) {
            resp.setContentType(MediaType.APPLICATION_JSON);
            resp.getWriter().print(tokenCookie.getIdToken());
            return AuthStatus.SEND_SUCCESS;
        } else if (req.getRequestURI().equals(userInfoUri)) {
            resp.setContentType(MediaType.APPLICATION_JSON);
            resp.getWriter().print(tokenCookie.getUserInfo());
            return AuthStatus.SEND_SUCCESS;
        } else {
            return AuthStatus.SUCCESS;
        }
    }

    /**
     * Handles "HEAD" requests that have a valid token. It handles the special
     * case then token URI or the user info URI is requested.
     *
     * @param req
     *            request
     * @param resp
     *            response
     * @param tokenCookie
     *            token cookie
     * @param requestCookieContext
     *            request cookie context
     * @param subject
     *            subject
     * @return {@link AuthStatus#SEND_SUCCESS} if processed by the module,
     *         {@link AuthStatus#SUCCESS} otherwise.
     * @throws IOException
     */
    private AuthStatus doHeadWithToken(final HttpServletRequest req,
            final HttpServletResponse resp, final TokenCookie tokenCookie,
            final String requestCookieContext, final Subject subject) {
        if (req.getRequestURI().equals(tokenUri)) {
            resp.setContentType(MediaType.APPLICATION_JSON);
            return AuthStatus.SEND_SUCCESS;
        } else if (req.getRequestURI().equals(userInfoUri)) {
            resp.setContentType(MediaType.APPLICATION_JSON);
            return AuthStatus.SEND_SUCCESS;
        } else {
            return AuthStatus.SUCCESS;
        }
    }

    /**
     * Handle unauthenticated operations when the request was not authenticated
     * yet.
     *
     * @param req
     *            request
     * @param resp
     *            response
     * @param requestCookieContext
     *            cookie context
     * @param subject
     *            subject
     * @return auth status
     */
    private AuthStatus doUnauthenticatedOperation(final HttpServletRequest req,
            final HttpServletResponse resp, final String requestCookieContext,
            final Subject subject) throws GeneralSecurityException, IOException {
        if (!isCalledFromResourceOwner(req)) {
            return redirectToAuthorizationEndpoint(req, resp);
        }

        final Client restClient = ClientBuilder.newClient();
        final OpenIDProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(
                restClient, moduleOptions);
        final JsonWebKeySet webKeys = getWebKeys(restClient, moduleOptions,
                oidProviderConfig);
        final OAuthToken token = getToken(restClient, req, oidProviderConfig);
        LOG.log(Level.FINEST, "tokenValue", token);
        final JsonObject claimsSet = Json.createReader(
                new ByteArrayInputStream(Utils.getJwsPayload(
                        token.getIdToken(), webKeys))).readObject();

        validateIdToken(clientId, claimsSet);

        final String iss = googleWorkaround(claimsSet.getString("iss"));
        final String issuer = googleWorkaround(oidProviderConfig.getIssuer());
        if (!iss.equals(issuer)) {
            LOG.log(Level.SEVERE, "issuerMismatch",
                    new Object[] { iss, issuer });
            throw new GeneralSecurityException(MessageFormat.format(
                    R.getString("issuerMismatch"), iss, issuer));
        }
        updateSubjectPrincipal(subject, claimsSet);

        final TokenCookie tokenCookie;
        if (Pattern.compile("\\bprofile\\b").matcher(scope).find()) {
            final Response userInfoResponse = restClient
                    .target(oidProviderConfig.getUserinfoEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .header("Authorization",
                            token.getTokenType() + " " + token.getAccessToken())
                            .get();
            if (userInfoResponse.getStatus() == 200) {
                tokenCookie = new TokenCookie(claimsSet,
                        userInfoResponse.readEntity(JsonObject.class));
            } else {
                LOG.log(Level.WARNING, "unableToGetProfile");
                tokenCookie = new TokenCookie(claimsSet);
            }
        } else {
            tokenCookie = new TokenCookie(claimsSet);
        }
        restClient.close();

        final Cookie idTokenCookie = new Cookie(NET_TRAJANO_AUTH_ID,
                tokenCookie.toCookieValue(clientId, clientSecret));
        idTokenCookie.setMaxAge(-1);
        idTokenCookie.setPath(requestCookieContext);
        resp.addCookie(idTokenCookie);

        final Cookie ageCookie = new Cookie(NET_TRAJANO_AUTH_AGE, "1");
        ageCookie.setMaxAge(Integer.parseInt(req.getParameter("expires_in")));
        ageCookie.setPath(requestCookieContext);
        resp.addCookie(ageCookie);

        final String stateEncoded = req.getParameter("state");
        final String redirectUri = new String(Base64.decode(stateEncoded));
        resp.sendRedirect(resp.encodeRedirectURL(redirectUri));
        return AuthStatus.SEND_CONTINUE;
    }

    /**
     * Gets the ID token. This ensures that both cookies are present, if not
     * then this will return <code>null</code>.
     *
     * @param req
     *            HTTP servlet request
     * @return ID token
     */
    private String getIdToken(final HttpServletRequest req) {
        final Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }
        String idToken = null;
        boolean foundAge = false;
        for (final Cookie cookie : cookies) {
            if (NET_TRAJANO_AUTH_ID.equals(cookie.getName())
                    && !isNullOrEmpty(cookie.getValue())) {
                idToken = cookie.getValue();
            } else if (NET_TRAJANO_AUTH_AGE.equals(cookie.getName())) {
                foundAge = true;
            }
            if (idToken != null && foundAge) {
                return idToken;
            }
        }
        return idToken;
    }

    /**
     * Lets subclasses change the provider configuration.
     *
     * @param restClient
     *            REST client
     * @param options
     *            module options
     * @return configuration
     * @throws AuthException
     *             wraps exceptions thrown during processing
     */
    protected abstract OpenIDProviderConfiguration getOpenIDProviderConfig(
            Client restClient, Map<String, String> options)
                    throws AuthException;

    /**
     * This gets the redirection endpoint URI.
     * <p>
     * If the redirection endpoint URI option is not set then this gets the base
     * URI for the application based on the request. This is used as the
     * redirect URI for OAuth.
     * <p>
     * If the redirection endpoint is set, then it is resolved against the
     * request URL.
     *
     * @param req
     *            request
     * @return redirection endpoint URI.
     */
    private URI getRedirectionEndpointUri(final HttpServletRequest req) {
        if (isNullOrEmpty(redirectionEndpointUri)) {
            final StringBuffer redirectUri = req.getRequestURL();
            // Get the third / character from the request URL should be the
            // start of the path.
            redirectUri.replace(
                    redirectUri.indexOf("/", redirectUri.indexOf("/",
                            redirectUri.indexOf("/") + 1) + 1), redirectUri
                            .length(), req.getContextPath());
            return URI.create(redirectUri.toString());
        } else {
            return URI.create(req.getRequestURL().toString()).resolve(
                    redirectionEndpointUri);
        }
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
        return new Class<?>[] { HttpServletRequest.class,
                HttpServletResponse.class };
    }

    /**
     * Sends a request to the token endpoint to get the token for the code.
     *
     * @param restClient
     *            REST client
     * @param req
     *            servlet request
     * @param oidProviderConfig
     *            OpenID provider config
     * @return token response
     */
    private OAuthToken getToken(final Client restClient,
            final HttpServletRequest req,
            final OpenIDProviderConfiguration oidProviderConfig) {
        final MultivaluedMap<String, String> requestData = new MultivaluedHashMap<>();
        requestData.putSingle(CODE, req.getParameter("code"));
        requestData.putSingle(CLIENT_ID, clientId);
        requestData.putSingle(CLIENT_SECRET, clientSecret);
        requestData.putSingle(GRANT_TYPE, "authorization_code");
        requestData.putSingle(REDIRECT_URI, getRedirectionEndpointUri(req)
                .toASCIIString());

        return restClient.target(oidProviderConfig.getTokenEndpoint())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.form(requestData), OAuthToken.class);
    }

    /**
     * Gets the web keys from the options and the OpenID provider configuration.
     * This may be overridden by clients.
     *
     * @param restClient
     *            REST client
     * @param options
     *            module options
     * @param config
     *            provider configuration
     * @return web keys
     * @throws GeneralSecurityException
     *             wraps exceptions thrown during processing
     */
    protected JsonWebKeySet getWebKeys(final Client restClient,
            final Map<String, String> options,
            final OpenIDProviderConfiguration config)
                    throws GeneralSecurityException {
        return new JsonWebKeySet(restClient.target(config.getJwksUri())
                .request().get(JsonObject.class));
    }

    /**
     * Workaround for the issuer value for Google. This was documented in
     * 15.6.2. of the spec. In which case if the issuer does not start with
     * https:// it will prepend it.
     *
     * @param issuer
     *            issuer
     * @return updated issuer
     */
    private String googleWorkaround(final String issuer) {
        if (issuer.startsWith(HTTPS_PREFIX)) {
            return issuer;
        }
        return HTTPS_PREFIX + issuer;
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
    @SuppressWarnings("unchecked")
    @Override
    public void initialize(final MessagePolicy requestPolicy,
            final MessagePolicy responsePolicy, final CallbackHandler h,
            @SuppressWarnings("rawtypes") final Map options)
                    throws AuthException {
        handler = h;
        try {
            moduleOptions = options;
            clientId = moduleOptions.get(CLIENT_ID_KEY);
            if (clientId == null) {
                LOG.log(Level.SEVERE, "missingOption", CLIENT_ID_KEY);
                throw new AuthException(MessageFormat.format(
                        R.getString("missingOption"), CLIENT_ID_KEY));
            }
            cookieContext = moduleOptions.get(COOKIE_CONTEXT_KEY);
            redirectionEndpointUri = moduleOptions
                    .get(REDIRECTION_ENDPOINT_URI_KEY);
            tokenUri = moduleOptions.get(TOKEN_URI_KEY);
            userInfoUri = moduleOptions.get(USERINFO_URI_KEY);
            scope = moduleOptions.get(SCOPE_KEY);
            if (isNullOrEmpty(scope)) {
                scope = "openid";
            }
            clientSecret = moduleOptions.get(CLIENT_SECRET_KEY);
            if (clientSecret == null) {
                LOG.log(Level.SEVERE, "missingOption", CLIENT_SECRET_KEY);
                throw new AuthException(MessageFormat.format(
                        R.getString("missingOption"), CLIENT_SECRET_KEY));
            }
            LOG.log(Level.CONFIG, "options", moduleOptions);
        } catch (final Exception e) {
            // Should not happen
            LOG.log(Level.SEVERE, "initializeException", e);
            throw new AuthException(MessageFormat.format(
                    R.getString("initializeException"), e.getMessage()));
        }
    }

    /**
     * Checks to see whether the {@link ServerAuthModule} is called by the
     * resource owner. This is indicated by the presence of a <code>code</code>
     * and a <code>state</code> on the URL and is an idempotent request (i.e.
     * GET or HEAD). The resource owner would be a web browser that got a
     * redirect sent by the OAuth 2.0 provider.
     *
     * @param req
     *            HTTP servlet request
     * @return the module is called by the resource owner.
     */
    private boolean isCalledFromResourceOwner(final HttpServletRequest req) {
        if (!isNullOrEmpty(redirectionEndpointUri)
                && !redirectionEndpointUri.equals(req.getRequestURI())) {
            return false;
        }

        return isIdempotentRequest(req)
                && !isNullOrEmpty(req.getParameter(CODE))
                && !isNullOrEmpty(req.getParameter(STATE));
    }

    /**
     * Sends a redirect to the authorization endpoint. It sends the current
     * request URI as the state so that the user can be redirected back to the
     * last place. However, this does not work for non-idempotent requests such
     * as POST in those cases it will result in a 401 error and
     * {@link AuthStatus#SEND_FAILURE}. For idempotent requests, it will build
     * the redirect URI and return {@link AuthStatus#SEND_CONTINUE}.
     *
     * @param req
     *            HTTP servlet request
     * @param resp
     *            HTTP servlet response
     * @return authentication status
     * @throws AuthException
     */
    private AuthStatus redirectToAuthorizationEndpoint(
            final HttpServletRequest req, final HttpServletResponse resp)
                    throws AuthException {
        URI authorizationEndpointUri = null;
        try {
            final String state;
            if (!isIdempotentRequest(req)) {
                state = req.getContextPath();
            } else {
                resp.sendError(HttpURLConnection.HTTP_UNAUTHORIZED,
                        "Unable to POST when unauthorized.");
                return AuthStatus.SEND_FAILURE;
            }
            final Client restClient = ClientBuilder.newClient();
            final OpenIDProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(
                    restClient, moduleOptions);
            restClient.close();
            authorizationEndpointUri = UriBuilder
                    .fromUri(oidProviderConfig.getAuthorizationEndpoint())
                    .queryParam(CLIENT_ID, clientId)
                    .queryParam(RESPONSE_TYPE, "code")
                    .queryParam(SCOPE, scope)
                    .queryParam(REDIRECT_URI, getRedirectionEndpointUri(req))
                    .queryParam(
                            STATE,
                            Base64.encodeWithoutPadding(state.getBytes("UTF-8")))
                            .build();
            resp.sendRedirect(authorizationEndpointUri.toASCIIString());
            return AuthStatus.SEND_CONTINUE;
        } catch (final IOException e) {
            // Should not happen
            LOG.log(Level.SEVERE, "sendRedirectException", new Object[] {
                    authorizationEndpointUri, e.getMessage() });
            throw new AuthException(MessageFormat.format(
                    R.getString("sendRedirectException"),
                    authorizationEndpointUri, e.getMessage()));
        }
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
     * Updates the principal for the subject. This is done through the
     * callbacks.
     *
     * @param subject
     *            subject
     * @param jwtPayload
     *            JWT payload
     * @throws AuthException
     * @throws GeneralSecurityException
     */
    private void updateSubjectPrincipal(final Subject subject,
            final JsonObject jwtPayload) throws GeneralSecurityException {
        try {
            final String iss = googleWorkaround(jwtPayload.getString("iss"));
            handler.handle(new Callback[] {
                    new CallerPrincipalCallback(subject, UriBuilder
                            .fromUri(iss).userInfo(jwtPayload.getString("sub"))
                            .build().toASCIIString()),
                            new GroupPrincipalCallback(subject, new String[] { iss }) });
        } catch (final IOException | UnsupportedCallbackException e) {
            // Should not happen
            LOG.log(Level.SEVERE, "updatePrincipalException", e.getMessage());
            throw new AuthException(MessageFormat.format(
                    R.getString("updatePrincipalException"), e.getMessage()));
        }
    }

    /**
     * Validates the request. The request must be secure otherwise it will
     * return {@link AuthStatus#FAILURE}. It then tries to build the token
     * cookie data if available, if the token is valid, subject is set correctly
     * and user info data if present is stored in the request, then call HTTP
     * method specific operations.
     *
     * @param messageInfo
     *            request and response
     * @param client
     *            client subject
     * @param serviceSubject
     *            service subject, ignored.
     * @return Auth status
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo,
            final Subject client, final Subject serviceSubject)
                    throws AuthException {
        final HttpServletRequest req = (HttpServletRequest) messageInfo
                .getRequestMessage();
        if (!req.isSecure()) {
            // Fail authorization 3.1.2.1
            return AuthStatus.FAILURE;
        }
        final HttpServletResponse resp = (HttpServletResponse) messageInfo
                .getResponseMessage();
        final String requestCookieContext;
        if (isNullOrEmpty(cookieContext)) {
            requestCookieContext = req.getContextPath();
        } else {
            requestCookieContext = cookieContext;
        }

        final String idToken = getIdToken(req);
        TokenCookie tokenCookie = null;
        if (idToken != null) {
            try {
                tokenCookie = new TokenCookie(idToken, clientId, clientSecret);
                validateIdToken(clientId, tokenCookie.getIdToken());
                updateSubjectPrincipal(client, tokenCookie.getIdToken());

                if (tokenCookie.getUserInfo() != null) {
                    req.setAttribute(NET_TRAJANO_AUTH_USERINFO,
                            tokenCookie.getUserInfo());
                }

            } catch (final IOException | GeneralSecurityException e) {
                LOG.log(Level.FINE, "invalidToken", e.getMessage());
            }
        }

        try {
            if (tokenCookie == null || tokenCookie.isExpired()) {
                return doUnauthenticatedOperation(req, resp,
                        requestCookieContext, client);
            }

            if (isGetRequest(req)) {
                return doGetWithToken(req, resp, tokenCookie,
                        requestCookieContext, client);
            } else if (isHeadRequest(req)) {
                return doHeadWithToken(req, resp, tokenCookie,
                        requestCookieContext, client);
            } else {
                return AuthStatus.SUCCESS;
            }
        } catch (final GeneralSecurityException e) {
            // Lower level as this may occur due to invalid or expired
            // tokens.
            LOG.log(Level.FINE, "validationWarning", e.getMessage());
            return AuthStatus.FAILURE;
        } catch (final Exception e) {
            // Should not happen
            LOG.log(Level.WARNING, "validationException", e);
            throw new AuthException(MessageFormat.format(
                    R.getString("validationException"), e.getMessage()));
        }
    }
}
