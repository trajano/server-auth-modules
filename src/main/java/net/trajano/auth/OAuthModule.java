package net.trajano.auth;

import static net.trajano.auth.internal.Utils.isNullOrEmpty;
import static net.trajano.auth.internal.Utils.validateIdToken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
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
     * Client ID option key.
     */
    public static final String CLIENT_ID_KEY = "client_id";

    /**
     * Client secret option key.
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
     * ID token cookie name.
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
     * Redirection endpoint URI key. The value is optional.
     */
    public static final String REDIRECTION_ENDPOINT_URI_KEY = "redirection_endpoint";

    /**
     * Scope option key. The value is optional and defaults to "openid"
     */
    public static final String SCOPE_KEY = "scope";

    /**
     * Supported message types.
     */
    private static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[] {
            HttpServletRequest.class, HttpServletResponse.class };

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
     * Redirection endpoint URI. This is set through "redirection.endpoint"
     * option. This must start with a forward slash. This value is optional.
     */
    private String redirectionEndpointUri;

    /**
     * Scope.
     */
    private String scope;

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
     * Gets a specific cookie.
     *
     * @param cookieName
     *            cookie name
     * @param req
     *            HTTP servlet request
     * @return ID token
     */
    private String getCookie(final String cookieName,
            final HttpServletRequest req) {
        final Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }
        for (final Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())
                    && !isNullOrEmpty(cookie.getValue())) {
                return cookie.getValue();
            }
        }
        return null;
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
     * {@inheritDoc}
     *
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
     * Sends a request to the token endpoint to get the token for the code.
     *
     * @param req
     *            servlet request
     * @param oidProviderConfig
     *            OpenID provider config
     * @return token response
     */
    private OAuthToken getToken(final HttpServletRequest req,
            final OpenIDProviderConfiguration oidProviderConfig) {
        final Client restClient = ClientBuilder.newClient();
        final MultivaluedMap<String, String> requestData = new MultivaluedHashMap<>();
        requestData.putSingle("code", req.getParameter("code"));
        requestData.putSingle("client_id", clientId);
        requestData.putSingle("client_secret", clientSecret);
        requestData.putSingle("grant_type", "authorization_code");
        requestData.putSingle("redirect_uri", getRedirectionEndpointUri(req)
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
            clientId = (String) options.get(CLIENT_ID_KEY);
            if (clientId == null) {
                LOG.log(Level.SEVERE, "missingOption", CLIENT_ID_KEY);
                throw new AuthException(MessageFormat.format(
                        R.getString("missingOption"), CLIENT_ID_KEY));
            }
            cookieContext = (String) options.get(COOKIE_CONTEXT_KEY);
            redirectionEndpointUri = (String) options
                    .get(REDIRECTION_ENDPOINT_URI_KEY);
            scope = (String) options.get(SCOPE_KEY);
            if (isNullOrEmpty(scope)) {
                scope = "openid";
            }
            clientSecret = (String) options.get(CLIENT_SECRET_KEY);
            if (clientId == null) {
                LOG.log(Level.SEVERE, "missingOption", CLIENT_SECRET_KEY);
                throw new AuthException(MessageFormat.format(
                        R.getString("missingOption"), CLIENT_SECRET_KEY));
            }
            moduleOptions = options;
            LOG.log(Level.CONFIG, "options", options);
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
     * and a <code>state</code> on the URL and the request is a "GET". The
     * resource owner would be a web browser that got a redirect sent by the
     * OAuth 2.0 provider.
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
        return "GET".equals(req.getMethod())
                && !isNullOrEmpty(req.getParameter("code"))
                && !isNullOrEmpty(req.getParameter("state"));
    }

    /**
     * Sends a redirect to the authorization endpoint. It sends the current
     * request URI as the state so that the user can be redirected back to the
     * last place. However, this does not work for POST requests in those cases
     * it will redirect back to the context root.
     *
     * @param req
     *            HTTP servlet request
     * @param resp
     *            HTTP servlet response
     * @param oidProviderConfig
     *            OpenID provider config
     * @throws AuthException
     */
    private void redirectToAuthorizationEndpoint(final HttpServletRequest req,
            final HttpServletResponse resp,
            final OpenIDProviderConfiguration oidProviderConfig)
            throws AuthException {
        final String state;
        if (!"GET".equals(req.getMethod()) && !"HEAD".equals(req.getMethod())) {
            state = req.getContextPath();
        } else {
            state = req.getRequestURI();
        }
        URI authorizationEndpointUri = null;
        try {
            authorizationEndpointUri = UriBuilder
                    .fromUri(oidProviderConfig.getAuthorizationEndpoint())
                    .queryParam("client_id", clientId)
                    .queryParam("response_type", "code")
                    .queryParam("scope", scope)
                    .queryParam("redirect_uri", getRedirectionEndpointUri(req))
                    .queryParam("state", Base64.encode(state.getBytes("UTF-8")))
                    .build();
            resp.sendRedirect(authorizationEndpointUri.toASCIIString());
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
     * {@inheritDoc}
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo,
            final Subject client, final Subject serviceSubject)
            throws AuthException {
        final HttpServletRequest req = (HttpServletRequest) messageInfo
                .getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo
                .getResponseMessage();
        final String idToken = getCookie(NET_TRAJANO_AUTH_ID, req);
        final String requestCookieContext;
        if (isNullOrEmpty(cookieContext)) {
            requestCookieContext = req.getContextPath();
        } else {
            requestCookieContext = cookieContext;
        }
        if (idToken != null && !isCalledFromResourceOwner(req)) {
            try {
                final TokenCookie tokenCookie = new TokenCookie(idToken,
                        clientId, clientSecret);
                validateIdToken(clientId, tokenCookie.getIdToken());
                updateSubjectPrincipal(client, tokenCookie.getIdToken());

                if (tokenCookie.getUserInfo() != null) {
                    req.setAttribute(NET_TRAJANO_AUTH_USERINFO,
                            tokenCookie.getUserInfo());
                }
                return AuthStatus.SUCCESS;
            } catch (final IOException | GeneralSecurityException e) {
                LOG.log(Level.FINE, "invalidToken", e.getMessage());
                final Cookie idTokenCookie = new Cookie(NET_TRAJANO_AUTH_ID, "");
                idTokenCookie.setMaxAge(0);
                idTokenCookie.setPath(requestCookieContext);
                resp.addCookie(idTokenCookie);

                final Client restClient = ClientBuilder.newClient();
                final OpenIDProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(
                        restClient, moduleOptions);
                redirectToAuthorizationEndpoint(req, resp, oidProviderConfig);
                restClient.close();
                return AuthStatus.SEND_CONTINUE;
            }
        } else if (!isCalledFromResourceOwner(req)) {
            final Client restClient = ClientBuilder.newClient();
            final OpenIDProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(
                    restClient, moduleOptions);
            redirectToAuthorizationEndpoint(req, resp, oidProviderConfig);
            restClient.close();
            return AuthStatus.SEND_CONTINUE;
        } else {
            if (!req.isSecure()) {
                // Fail authorization 3.1.2.1
                return AuthStatus.FAILURE;
            }
            try {
                final Client restClient = ClientBuilder.newClient();
                final OpenIDProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(
                        restClient, moduleOptions);
                final JsonWebKeySet webKeys = getWebKeys(restClient,
                        moduleOptions, oidProviderConfig);
                final OAuthToken token = getToken(req, oidProviderConfig);
                LOG.log(Level.FINEST, "tokenValue", token);
                final JsonObject claimsSet = Json.createReader(
                        new ByteArrayInputStream(Utils.getJwsPayload(
                                token.getIdToken(), webKeys))).readObject();

                validateIdToken(clientId, claimsSet);

                final String iss = googleWorkaround(claimsSet.getString("iss"));
                final String issuer = googleWorkaround(oidProviderConfig
                        .getIssuer());
                if (!iss.equals(issuer)) {
                    LOG.log(Level.SEVERE, "issuerMismatch", new Object[] { iss,
                            issuer });
                    throw new GeneralSecurityException(MessageFormat.format(
                            R.getString("issuerMismatch"), iss, issuer));
                }
                updateSubjectPrincipal(client, claimsSet);

                final TokenCookie tokenCookie;
                if (Pattern.compile("\\bprofile\\b").matcher(scope).find()) {
                    final Response userInfoResponse = restClient
                            .target(oidProviderConfig.getUserinfoEndpoint())
                            .request(MediaType.APPLICATION_JSON_TYPE)
                            .header("Authorization",
                                    token.getTokenType() + " "
                                            + token.getAccessToken()).get();
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

                final String stateEncoded = req.getParameter("state");
                final String redirectUri = new String(
                        Base64.decode(stateEncoded));
                resp.sendRedirect(resp.encodeRedirectURL(redirectUri));
                return AuthStatus.SEND_SUCCESS;
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
}
