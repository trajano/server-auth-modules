package net.trajano.auth.internal;

/**
 * OAuth Parameters registry. Contains the ones defined in 11.2.2. Initial
 * Registry Contents.
 *
 * @author Archimedes Trajano
 */
public final class OAuthParameters {
    /**
     * access_token.
     * <ul>
     * <li>Parameter usage location: authorization response, token response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String ACCESS_TOKEN = "access_token";

    /**
     * client_id.
     * <ul>
     * <li>Parameter usage location: authorization request, token request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String CLIENT_ID = "client_id";
    /**
     * client_secret.
     * <ul>
     * <li>Parameter usage location: token request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String CLIENT_SECRET = "client_secret";
    /**
     * code.
     * <ul>
     * <li>Parameter usage location: authorization response, token request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String CODE = "code";
    /**
     * error_description.
     * <ul>
     * <li>Parameter usage location: authorization response, token response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String ERROR_DESCRIPTION = "error_description";
    /**
     * error_uri.
     * <ul>
     * <li>Parameter usage location: authorization response, token response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String ERROR_URI = "error_uri";
    /**
     * expires_in.
     * <ul>
     * <li>Parameter usage location: authorization response, token response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String EXPIRES_IN = "expires_in";
    /**
     * grant_type.
     * <ul>
     * <li>Parameter usage location: token request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String GRANT_TYPE = "grant_type";
    /**
     * password.
     * <ul>
     * <li>Parameter usage location: token request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String PASSWORD = "password";
    /**
     * redirect_uri.
     * <ul>
     * <li>Parameter usage location: authorization request, token request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String REDIRECT_URI = "redirect_uri";
    /**
     * refresh_token.
     * <ul>
     * <li>Parameter usage location: token request, token response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String REFRESH_TOKEN = "refresh_token";
    /**
     * response_type.
     * <ul>
     * <li>Parameter usage location: authorization request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String RESPONSE_TYPE = "response_type";
    /**
     * scope.
     * <ul>
     * <li>Parameter usage location: authorization request, authorization
     * response, token request, token response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String SCOPE = "scope";
    /**
     * state.
     * <ul>
     * <li>Parameter usage location: authorization request, authorization
     * response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String STATE = "state";
    /**
     * token_type.
     * <ul>
     * <li>Parameter usage location: authorization response, token response
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String TOKEN_TYPE = "token_type";
    /**
     * username.
     * <ul>
     * <li>Parameter usage location: token request
     * <li>Change controller: IETF
     * <li>Specification document(s): RFC 6749
     * </ul>
     */
    public static final String USERNAME = "username";

    /**
     * Prevent instantiation of constants class.
     */
    private OAuthParameters() {

    }
}
