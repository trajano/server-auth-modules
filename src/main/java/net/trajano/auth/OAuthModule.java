package net.trajano.auth;

import static net.trajano.auth.internal.OAuthParameters.CLIENT_ID;
import static net.trajano.auth.internal.OAuthParameters.CODE;
import static net.trajano.auth.internal.OAuthParameters.GRANT_TYPE;
import static net.trajano.auth.internal.OAuthParameters.REDIRECT_URI;
import static net.trajano.auth.internal.OAuthParameters.RESPONSE_TYPE;
import static net.trajano.auth.internal.OAuthParameters.SCOPE;
import static net.trajano.auth.internal.OAuthParameters.STATE;
import static net.trajano.auth.internal.Utils.isGetRequest;
import static net.trajano.auth.internal.Utils.isHeadRequest;
import static net.trajano.auth.internal.Utils.isNullOrEmpty;
import static net.trajano.auth.internal.Utils.isRetrievalRequest;
import static net.trajano.auth.internal.Utils.validateIdToken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Map;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
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
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.auth.internal.Base64;
import net.trajano.auth.internal.CipherUtil;
import net.trajano.auth.internal.JsonWebKeySet;
import net.trajano.auth.internal.NullHostnameVerifier;
import net.trajano.auth.internal.NullX509TrustManager;
import net.trajano.auth.internal.OAuthToken;
import net.trajano.auth.internal.OpenIDProviderConfiguration;
import net.trajano.auth.internal.TokenCookie;
import net.trajano.auth.internal.Utils;

/**
 * OAuth 2.0 server authentication module. This is an implementation of the <a
 * href="http://tools.ietf.org/html/rfc6749">OAuth 2.0 authentication
 * framework</a>. This assumes no HttpSessions which makes it useful for RESTful
 * applications and uses the OAuth token to manage the authentication state. The
 * e-mail addresses are not requested.
 *
 * @author Archimedes Trajano
 */
public abstract class OAuthModule implements ServerAuthModule, ServerAuthContext {

    /**
     * Access token attribute name.
     */
    public static final String ACCESS_TOKEN_KEY = "auth_access";

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
     * Disable HTTP certificate checks key. This this is set to true, the auth
     * module will disable HTTPS certificate checks for the REST client
     * connections. This should only be used in development.
     */
    public static final String DISABLE_CERTIFICATE_CHECKS_KEY = "disable_certificate_checks";

    /**
     * https prefix.
     */
    private static final String HTTPS_PREFIX = "https://";

    /**
     * Open ID token attribute name.
     */
    public static final String ID_TOKEN_KEY = "auth_idtoken";

    /**
     * Logger.
     */
    private static final Logger LOG;

    /**
     * Logger for configuration.
     */
    private static final Logger LOGCONFIG;

    /**
     * URI to go to when the user has logged out relative to the context path.
     */
    public static final String LOGOUT_GOTO_URI_KEY = "logout_goto_uri";

    public static final String LOGOUT_URI_KEY = "logout_uri";

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    /**
     * Age cookie name. The value of this cookie is an encrypted version of the
     * IP Address and will expire based on the max age of the token.
     */
    public static final String NET_TRAJANO_AUTH_AGE = "net.trajano.auth.age";

    /**
     * ID token cookie name. This one expires when the browser closes.
     */
    public static final String NET_TRAJANO_AUTH_ID = "net.trajano.auth.id";

    /**
     * Nonce cookie name. This one expires when the browser closes.
     */
    public static final String NET_TRAJANO_AUTH_NONCE = "net.trajano.auth.nonce";

    /**
     * Resource bundle.
     */
    private static final ResourceBundle R;

    /**
     * Redirection endpoint URI key. The value is optional and defaults to the
     * context root of the application.
     */
    public static final String REDIRECTION_ENDPOINT_URI_KEY = "redirection_endpoint"; //$NON-NLS-1$
    /**
     * Refresh token attribute name.
     */
    public static final String REFRESH_TOKEN_KEY = "auth_refresh";
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
     * User info attribute name.
     */
    public static final String USERINFO_KEY = "auth_userinfo";

    /**
     * User Info URI key. The value is optional and if not specified, the
     * userinfo request functionality will not be available.
     */
    public static final String USERINFO_URI_KEY = "userinfo_uri";

    static {
        LOG = Logger.getLogger("net.trajano.auth.oauthsam", MESSAGES);
        LOGCONFIG = Logger.getLogger("net.trajano.auth.oauthsam.config", MESSAGES);
        R = ResourceBundle.getBundle(MESSAGES);
    }

    /**
     * Client ID. This is set through {@value #CLIENT_ID_KEY} option.
     */
    private String clientId;

    /**
     * Client secret. This is set through {@value #CLIENT_SECRET_KEY} option.
     */
    private String clientSecret;

    /**
     * Cookie context path. Set through through "cookie_context" option. This is
     * optional.
     */
    private String cookieContext;

    /**
     * Callback handler.
     */
    private CallbackHandler handler;

    private String logoutGotoUri;

    private String logoutUri;

    /**
     * Flag to indicate that authentication is mandatory.
     */
    private boolean mandatory;

    /**
     * Options for the module.
     */
    private Map<String, String> moduleOptions;

    /**
     * Randomizer.
     */
    private final Random random = new SecureRandom();

    /**
     * Redirection endpoint URI. This is set through "redirection_endpoint"
     * option. This must start with a forward slash. This value is optional.
     */
    private String redirectionEndpointUri;

    /**
     * REST Client. This is not final so a different one can be put in for
     * testing.
     */
    private Client restClient;

    /**
     * Scope.
     */
    private String scope;

    /**
     * Secret key used for module level ciphers.
     */
    private SecretKey secret;

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
     * Builds a REST client that bypasses SSL security checks. Made public so it
     * can be used for testing.
     *
     * @return JAX-RS client.
     */
    public Client buildUnsecureRestClient() throws GeneralSecurityException {
        final SSLContext context = SSLContext.getInstance("TLSv1");
        final TrustManager[] trustManagerArray = { NullX509TrustManager.INSTANCE };
        context.init(null, trustManagerArray, null);
        return ClientBuilder.newBuilder()
                .hostnameVerifier(NullHostnameVerifier.INSTANCE)
                .sslContext(context)
                .build();
    }

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

    private void deleteAuthCookies(final HttpServletResponse resp) {

        for (final String cookieName : new String[] { NET_TRAJANO_AUTH_ID, NET_TRAJANO_AUTH_AGE, NET_TRAJANO_AUTH_NONCE }) {
            final Cookie deleteCookie = new Cookie(cookieName, "");
            deleteCookie.setMaxAge(0);
            deleteCookie.setPath(cookieContext);
            resp.addCookie(deleteCookie);
        }
    }

    /**
     * Client ID.
     *
     * @return the client ID.
     */
    protected String getClientId() {

        return clientId;
    }

    /**
     * Client Secret.
     *
     * @return the client secret.
     */
    protected String getClientSecret() {

        return clientSecret;
    }

    /**
     * Gets the ID token. This ensures that both cookies are present, if not
     * then this will return <code>null</code>.
     *
     * @param req
     *            HTTP servlet request
     * @return ID token
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private String getIdToken(final HttpServletRequest req) throws GeneralSecurityException, IOException {

        final Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }
        String idToken = null;
        boolean foundAge = false;
        for (final Cookie cookie : cookies) {
            if (NET_TRAJANO_AUTH_ID.equals(cookie.getName()) && !isNullOrEmpty(cookie.getValue())) {
                idToken = cookie.getValue();
            } else if (NET_TRAJANO_AUTH_AGE.equals(cookie.getName())) {
                final String remoteAddr = req.getRemoteAddr();
                final String cookieAddr = new String(CipherUtil.decrypt(Base64.decode(cookie.getValue()), secret), "US-ASCII");
                if (!remoteAddr.equals(cookieAddr)) {
                    throw new AuthException(MessageFormat.format(R.getString("ipaddressMismatch"), remoteAddr, cookieAddr));
                }
                foundAge = true;
            }
            if (idToken != null && foundAge) {
                return idToken;
            }
        }
        return null;
    }

    /**
     * Gets the nonce from the cookie.
     *
     * @param req
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private String getNonceFromCookie(final HttpServletRequest req) throws GeneralSecurityException, IOException {
        final Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }

        for (final Cookie cookie : cookies) {
            if (NET_TRAJANO_AUTH_NONCE.equals(cookie.getName())) {
                return new String(CipherUtil.decrypt(Base64.decode(cookie.getValue()), secret), "US-ASCII");
            }
        }
        return null;
    }

    /**
     * Lets subclasses change the provider configuration.
     *
     * @param req
     *            request message
     * @param client
     *            REST client
     * @param options
     *            module options
     * @return configuration
     * @throws AuthException
     *             wraps exceptions thrown during processing
     */
    protected abstract OpenIDProviderConfiguration getOpenIDProviderConfig(HttpServletRequest req, Client client, Map<String, String> options) throws AuthException;

    /**
     * This gets the redirection endpoint URI. It uses the
     * {@link #REDIRECTION_ENDPOINT_URI_KEY} option resolved against the request
     * URL to get the host name.
     *
     * @param req
     *            request
     * @return redirection endpoint URI.
     */
    protected URI getRedirectionEndpointUri(final HttpServletRequest req) {

        return URI.create(req.getRequestURL()
                .toString())
                .resolve(redirectionEndpointUri);
    }

    /**
     * Gets an option and ensures it is present.
     *
     * @param optionKey
     *            option key
     * @return the option value
     * @throws AuthException
     *             missing option exception
     */
    private String getRequiredOption(final String optionKey) throws AuthException {

        final String optionValue = moduleOptions.get(optionKey);
        if (optionValue == null) {
            LOG.log(Level.SEVERE, "missingOption", optionKey);
            throw new AuthException(MessageFormat.format(R.getString("missingOption"), optionKey));
        }
        return optionValue;
    }

    /**
     * REST client.
     *
     * @return REST client
     */
    protected Client getRestClient() {

        return restClient;
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
     * Sends a request to the token endpoint to get the token for the code.
     *
     * @param req
     *            servlet request
     * @param oidProviderConfig
     *            OpenID provider config
     * @return token response
     */
    protected OAuthToken getToken(final HttpServletRequest req, final OpenIDProviderConfiguration oidProviderConfig) throws IOException {

        final MultivaluedMap<String, String> requestData = new MultivaluedHashMap<>();
        requestData.putSingle(CODE, req.getParameter("code"));
        requestData.putSingle(GRANT_TYPE, "authorization_code");
        requestData.putSingle(REDIRECT_URI, getRedirectionEndpointUri(req).toASCIIString());

        try {
            final String authorization = "Basic " + Base64.encode((clientId + ":" + clientSecret).getBytes("UTF8"));
            final OAuthToken authorizationTokenResponse = restClient.target(oidProviderConfig.getTokenEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .header("Authorization", authorization)
                    .post(Entity.form(requestData), OAuthToken.class);
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("authorization token response =  " + authorizationTokenResponse);
            }
            return authorizationTokenResponse;
        } catch (final BadRequestException e) {
            // workaround for google that does not support BASIC authentication
            // on their endpoint.
            requestData.putSingle(CLIENT_ID, clientId);
            requestData.putSingle(CLIENT_SECRET_KEY, clientSecret);
            final OAuthToken authorizationTokenResponse = restClient.target(oidProviderConfig.getTokenEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .post(Entity.form(requestData), OAuthToken.class);
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("authorization token response =  " + authorizationTokenResponse);
            }
            return authorizationTokenResponse;
        }
    }

    /**
     * Gets the web keys from the options and the OpenID provider configuration.
     * This may be overridden by clients.
     *
     * @param options
     *            module options
     * @param config
     *            provider configuration
     * @return web keys
     * @throws GeneralSecurityException
     *             wraps exceptions thrown during processing
     */
    protected JsonWebKeySet getWebKeys(final Map<String, String> options, final OpenIDProviderConfiguration config) throws GeneralSecurityException {

        return new JsonWebKeySet(restClient.target(config.getJwksUri())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(JsonObject.class));
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
     * Handles the callback.
     *
     * @param req
     *            servlet request
     * @param resp
     *            servlet response
     * @param subject
     *            user subject
     * @return status
     * @throws GeneralSecurityException
     */
    private AuthStatus handleCallback(final HttpServletRequest req, final HttpServletResponse resp, final Subject subject) throws GeneralSecurityException, IOException {

        final OpenIDProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(req, restClient, moduleOptions);
        final OAuthToken token = getToken(req, oidProviderConfig);
        final JsonWebKeySet webKeys = getWebKeys(moduleOptions, oidProviderConfig);

        LOG.log(Level.FINEST, "tokenValue", token);
        final JsonObject claimsSet = Json.createReader(new ByteArrayInputStream(Utils.getJwsPayload(token.getIdToken(), webKeys)))
                .readObject();

        final String nonce = getNonceFromCookie(req);
        validateIdToken(clientId, claimsSet, nonce);

        final Cookie deleteNonceCookie = new Cookie(NET_TRAJANO_AUTH_NONCE, "");
        deleteNonceCookie.setMaxAge(0);
        deleteNonceCookie.setPath(cookieContext);
        resp.addCookie(deleteNonceCookie);

        final String iss = googleWorkaround(claimsSet.getString("iss"));
        final String issuer = googleWorkaround(oidProviderConfig.getIssuer());
        if (!iss.equals(issuer)) {
            LOG.log(Level.SEVERE, "issuerMismatch", new Object[] { iss, issuer });
            throw new GeneralSecurityException(MessageFormat.format(R.getString("issuerMismatch"), iss, issuer));
        }
        updateSubjectPrincipal(subject, claimsSet);

        final TokenCookie tokenCookie;
        if (oidProviderConfig.getUserinfoEndpoint() != null && Pattern.compile("\\bprofile\\b")
                .matcher(scope)
                .find()) {
            final Response userInfoResponse = restClient.target(oidProviderConfig.getUserinfoEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .header("Authorization", token.getTokenType() + " " + token.getAccessToken())
                    .get();
            if (userInfoResponse.getStatus() == 200) {
                tokenCookie = new TokenCookie(token.getAccessToken(), token.getRefreshToken(), claimsSet, userInfoResponse.readEntity(JsonObject.class));
            } else {
                LOG.log(Level.WARNING, "unableToGetProfile");
                tokenCookie = new TokenCookie(claimsSet);
            }
        } else {
            tokenCookie = new TokenCookie(claimsSet);
        }

        final String requestCookieContext;
        if (isNullOrEmpty(cookieContext)) {
            requestCookieContext = req.getContextPath();
        } else {
            requestCookieContext = cookieContext;
        }

        final Cookie idTokenCookie = new Cookie(NET_TRAJANO_AUTH_ID, tokenCookie.toCookieValue(clientId, clientSecret));
        idTokenCookie.setMaxAge(-1);
        idTokenCookie.setSecure(true);
        idTokenCookie.setHttpOnly(true);
        idTokenCookie.setPath(requestCookieContext);
        resp.addCookie(idTokenCookie);

        final Cookie ageCookie = new Cookie(NET_TRAJANO_AUTH_AGE, Base64.encodeWithoutPadding(CipherUtil.encrypt(req.getRemoteAddr()
                .getBytes("US-ASCII"), secret)));
        if (isNullOrEmpty(req.getParameter("expires_in"))) {
            ageCookie.setMaxAge(3600);

        } else {
            ageCookie.setMaxAge(Integer.parseInt(req.getParameter("expires_in")));
        }
        ageCookie.setPath(requestCookieContext);
        ageCookie.setSecure(true);
        ageCookie.setHttpOnly(true);
        resp.addCookie(ageCookie);

        final String stateEncoded = req.getParameter("state");
        final String redirectUri = new String(Base64.decode(stateEncoded));
        resp.sendRedirect(resp.encodeRedirectURL(req.getContextPath() + redirectUri));

        return AuthStatus.SEND_SUCCESS;
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
    public void initialize(final MessagePolicy requestPolicy, final MessagePolicy responsePolicy, final CallbackHandler h, @SuppressWarnings("rawtypes") final Map options) throws AuthException {

        try {
            moduleOptions = options;
            clientId = getRequiredOption(CLIENT_ID_KEY);
            cookieContext = moduleOptions.get(COOKIE_CONTEXT_KEY);
            redirectionEndpointUri = getRequiredOption(REDIRECTION_ENDPOINT_URI_KEY);
            tokenUri = moduleOptions.get(TOKEN_URI_KEY);
            userInfoUri = moduleOptions.get(USERINFO_URI_KEY);
            logoutUri = moduleOptions.get(LOGOUT_URI_KEY);
            logoutGotoUri = moduleOptions.get(LOGOUT_GOTO_URI_KEY);
            scope = moduleOptions.get(SCOPE_KEY);
            if (isNullOrEmpty(scope)) {
                scope = "openid";
            }
            clientSecret = getRequiredOption(CLIENT_SECRET_KEY);
            LOGCONFIG.log(Level.CONFIG, "options", moduleOptions);

            handler = h;
            mandatory = requestPolicy.isMandatory();
            secret = CipherUtil.buildSecretKey(clientId, clientSecret);

            if (restClient == null) {
                if (moduleOptions.get(DISABLE_CERTIFICATE_CHECKS_KEY) != null && Boolean.valueOf(moduleOptions.get(DISABLE_CERTIFICATE_CHECKS_KEY))) {
                    restClient = buildUnsecureRestClient();
                } else {
                    restClient = ClientBuilder.newClient();
                }

            }
        } catch (final Exception e) {
            // Should not happen
            LOG.log(Level.SEVERE, "initializeException", e);
            throw new AuthException(MessageFormat.format(R.getString("initializeException"), e.getMessage()));
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
    public boolean isCallback(final HttpServletRequest req) {

        return moduleOptions.get(REDIRECTION_ENDPOINT_URI_KEY)
                .equals(req.getRequestURI()) && isRetrievalRequest(req) && !isNullOrEmpty(req.getParameter(CODE)) && !isNullOrEmpty(req.getParameter(STATE));
    }

    /**
     * Generate the next nonce.
     *
     * @return nonce
     */
    private String nextNonce() {
        final byte[] bytes = new byte[8];
        random.nextBytes(bytes);
        return Base64.encodeWithoutPadding(bytes);
    }

    /**
     * Builds the token cookie and updates the subject principal and sets the
     * token and user info attribute in the request. Any exceptions or
     * validation problems during validation will make this return
     * <code>null</code> to indicate that there was no valid token.
     *
     * @param subject
     *            subject
     * @param req
     *            servlet request
     * @return token cookie.
     */
    private TokenCookie processTokenCookie(final Subject subject, final HttpServletRequest req) {

        try {
            final String idToken = getIdToken(req);
            TokenCookie tokenCookie = null;
            if (idToken != null) {
                tokenCookie = new TokenCookie(idToken, secret);
                validateIdToken(clientId, tokenCookie.getIdToken(), null);
                updateSubjectPrincipal(subject, tokenCookie.getIdToken());

                req.setAttribute(ACCESS_TOKEN_KEY, tokenCookie.getAccessToken());
                req.setAttribute(REFRESH_TOKEN_KEY, tokenCookie.getRefreshToken());
                req.setAttribute(ID_TOKEN_KEY, tokenCookie.getIdToken());
                if (tokenCookie.getUserInfo() != null) {
                    req.setAttribute(USERINFO_KEY, tokenCookie.getUserInfo());
                }
            }
            return tokenCookie;
        } catch (final GeneralSecurityException | IOException e) {
            LOG.log(Level.FINE, "invalidToken", e.getMessage());
            LOG.throwing(this.getClass()
                    .getName(), "validateRequest", e);
            return null;
        }
    }

    /**
     * Sends a redirect to the authorization endpoint. It sends the current
     * request URI as the state so that the user can be redirected back to the
     * last place. However, this does not work for non-idempotent requests such
     * as POST in those cases it will result in a 401 error and
     * {@link AuthStatus#SEND_FAILURE}. For idempotent requests, it will build
     * the redirect URI and return {@link AuthStatus#SEND_CONTINUE}. It will
     * also destroy the cookies used for authorization as part of the response.
     * <p>
     * It stores an encrypted nonce in the cookies and uses it to verify the
     * nonce value later.
     * </p>
     *
     * @param req
     *            HTTP servlet request
     * @param resp
     *            HTTP servlet response
     * @param reason
     *            reason for redirect (used for logging)
     * @return authentication status
     * @throws AuthException
     */
    private AuthStatus redirectToAuthorizationEndpoint(final HttpServletRequest req, final HttpServletResponse resp, final String reason) throws AuthException {

        LOG.log(Level.FINE, "redirecting", new Object[] { reason });
        URI authorizationEndpointUri = null;
        try {
            final OpenIDProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(req, restClient, moduleOptions);

            final StringBuilder stateBuilder = new StringBuilder(req.getRequestURI()
                    .substring(req.getContextPath()
                            .length()));
            if (req.getQueryString() != null) {
                stateBuilder.append('?');
                stateBuilder.append(req.getQueryString());
            }
            final String state = Base64.encodeWithoutPadding(stateBuilder.toString()
                    .getBytes("UTF-8"));

            final String requestCookieContext;
            if (isNullOrEmpty(cookieContext)) {
                requestCookieContext = req.getContextPath();
            } else {
                requestCookieContext = cookieContext;
            }

            final String nonce = nextNonce();
            final Cookie nonceCookie = new Cookie(NET_TRAJANO_AUTH_NONCE, Base64.encodeWithoutPadding(CipherUtil.encrypt(nonce.getBytes(), secret)));
            nonceCookie.setMaxAge(-1);
            nonceCookie.setPath(requestCookieContext);
            nonceCookie.setHttpOnly(true);
            nonceCookie.setSecure(true);
            resp.addCookie(nonceCookie);
            authorizationEndpointUri = UriBuilder.fromUri(oidProviderConfig.getAuthorizationEndpoint())
                    .queryParam(CLIENT_ID, clientId)
                    .queryParam(RESPONSE_TYPE, "code")
                    .queryParam(SCOPE, scope)
                    .queryParam(REDIRECT_URI, URI.create(req.getRequestURL()
                            .toString())
                            .resolve(moduleOptions.get(REDIRECTION_ENDPOINT_URI_KEY)))
                            .queryParam(STATE, state)
                            .queryParam("nonce", nonce)
                            .build();
            deleteAuthCookies(resp);

            resp.sendRedirect(authorizationEndpointUri.toASCIIString());
            return AuthStatus.SEND_CONTINUE;
        } catch (final IOException | GeneralSecurityException e) {
            // Should not happen
            LOG.log(Level.SEVERE, "sendRedirectException", new Object[] { authorizationEndpointUri, e.getMessage() });
            LOG.throwing(this.getClass()
                    .getName(), "redirectToAuthorizationEndpoint", e);
            throw new AuthException(MessageFormat.format(R.getString("sendRedirectException"), authorizationEndpointUri, e.getMessage()));
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
    public AuthStatus secureResponse(final MessageInfo messageInfo, final Subject subject) throws AuthException {

        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * Override REST client for testing.
     *
     * @param restClient
     *            REST client. May be mocked.
     */
    public void setRestClient(final Client restClient) {

        this.restClient = restClient;
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
    private void updateSubjectPrincipal(final Subject subject, final JsonObject jwtPayload) throws GeneralSecurityException {

        try {
            final String iss = googleWorkaround(jwtPayload.getString("iss"));
            handler.handle(new Callback[] { new CallerPrincipalCallback(subject, UriBuilder.fromUri(iss)
                    .userInfo(jwtPayload.getString("sub"))
                    .build()
                    .toASCIIString()), new GroupPrincipalCallback(subject, new String[] { iss }) });
        } catch (final IOException | UnsupportedCallbackException e) {
            // Should not happen
            LOG.log(Level.SEVERE, "updatePrincipalException", e.getMessage());
            LOG.throwing(this.getClass()
                    .getName(), "updateSubjectPrincipal", e);
            throw new AuthException(MessageFormat.format(R.getString("updatePrincipalException"), e.getMessage()));
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
     * @param clientSubject
     *            client subject
     * @param serviceSubject
     *            service subject, ignored.
     * @return Auth status
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo, final Subject clientSubject, final Subject serviceSubject) throws AuthException {

        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();

        try {
            final TokenCookie tokenCookie = processTokenCookie(clientSubject, req);

            if (tokenCookie != null && req.isSecure() && isGetRequest(req) && req.getRequestURI()
                    .equals(tokenUri)) {
                resp.setContentType(MediaType.APPLICATION_JSON);
                resp.getWriter()
                .print(tokenCookie.getIdToken());
                return AuthStatus.SEND_SUCCESS;
            }

            if (tokenCookie != null && req.isSecure() && isGetRequest(req) && req.getRequestURI()
                    .equals(userInfoUri)) {
                resp.setContentType(MediaType.APPLICATION_JSON);
                resp.getWriter()
                .print(tokenCookie.getUserInfo());
                return AuthStatus.SEND_SUCCESS;
            }

            if (tokenCookie != null && req.isSecure() && isGetRequest(req) && req.getRequestURI()
                    .equals(logoutUri)) {
                deleteAuthCookies(resp);
                if (logoutGotoUri == null) {
                    resp.sendRedirect(req.getServletContext() + "/");
                } else {
                    resp.sendRedirect(logoutGotoUri);
                }
                return AuthStatus.SEND_SUCCESS;
            }

            if (!mandatory && !req.isSecure()) {
                // successful if the module is not mandatory and the channel is
                // not secure.
                return AuthStatus.SUCCESS;
            }

            if (!req.isSecure() && mandatory) {
                // Fail authorization 3.1.2.1
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, R.getString("SSLReq"));
                return AuthStatus.SEND_FAILURE;
            }

            if (!req.isSecure() && isCallback(req)) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, R.getString("SSLReq"));
                return AuthStatus.SEND_FAILURE;
            }

            if (req.isSecure() && isCallback(req)) {
                return handleCallback(req, resp, clientSubject);
            }

            if (!mandatory || tokenCookie != null && !tokenCookie.isExpired()) {
                return AuthStatus.SUCCESS;
            }
            if (req.isSecure() && isHeadRequest(req) && req.getRequestURI()
                    .equals(tokenUri)) {
                resp.setContentType(MediaType.APPLICATION_JSON);
                return AuthStatus.SEND_SUCCESS;
            }

            if (req.getRequestURI()
                    .equals(userInfoUri) && isHeadRequest(req)) {
                resp.setContentType(MediaType.APPLICATION_JSON);
                return AuthStatus.SEND_SUCCESS;

            }
            if (!isRetrievalRequest(req)) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, "Unable to POST when unauthorized.");
                return AuthStatus.SEND_FAILURE;
            }

            return redirectToAuthorizationEndpoint(req, resp, "request is not valid");
        } catch (final Exception e) {
            // Any problems with the data should be caught and force redirect to
            // authorization endpoint.
            LOG.log(Level.FINE, "validationException", e.getMessage());
            LOG.throwing(this.getClass()
                    .getName(), "validateRequest", e);
            return redirectToAuthorizationEndpoint(req, resp, e.getMessage());
        }
    }
}
