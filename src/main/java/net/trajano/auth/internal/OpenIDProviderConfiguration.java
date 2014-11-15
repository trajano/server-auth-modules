package net.trajano.auth.internal;

import java.net.URI;
import java.util.List;

import javax.json.JsonObject;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * OpenID Provider configuration.
 *
 * @author Archimedes Trajano
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class OpenIDProviderConfiguration {
    /**
     * Authorization endpoint.
     */
    @XmlElement(name = "authorization_endpoint")
    private URI authorizationEndpoint;

    /**
     * List of ID Token algorithms supports.
     */
    @XmlElement(name = "id_token_alg_values_supported")
    private List<String> idTokenAlgValuesSupported;

    /**
     * Issuer.
     */
    @XmlElement(name = "issuer")
    private String issuer;

    /**
     * JSON Web Keys URI.
     */
    @XmlElement(name = "jwks_uri")
    private URI jwksUri;

    /**
     * Response types supported.
     */
    @XmlElement(name = "response_types_supported")
    private List<String> responseTypesSupported;

    /**
     * Revocation end point.
     */
    @XmlElement(name = "revocation_endpoint")
    private URI revocationEndpoint;

    /**
     * Subject types supported.
     */
    @XmlElement(name = "subject_types_supported")
    private List<String> subjectTypesSupported;

    /**
     * Token end point.
     */
    @XmlElement(name = "token_endpoint")
    private URI tokenEndpoint;

    /**
     * Token endpoint auth methods supported.
     */
    @XmlElement(name = "token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported;
    /**
     * Userinfo endpoint. Used to get information about the currently
     * authenticated user.
     */
    @XmlElement(name = "userinfo_endpoint")
    private URI userinfoEndpoint;

    /**
     * Constructs the object with the defaults.
     */
    public OpenIDProviderConfiguration() {

    }

    /**
     * Constructs the object using JSON.
     *
     * @param jsonObject
     *            JSON object
     */
    public OpenIDProviderConfiguration(final JsonObject jsonObject) {
        setAuthorizationEndpoint(URI.create(jsonObject.getString("authorization_endpoint")));
        setTokenEndpoint(URI.create(jsonObject.getString("token_endpoint")));
        setIssuer(jsonObject.getString("issuer"));
        setRevocationEndpoint(URI.create(jsonObject.getString("revocation_endpoint")));
        setJwksUri(URI.create(jsonObject.getString("jwks_uri")));
    }

    public URI getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public List<String> getIdTokenAlgValuesSupported() {
        return idTokenAlgValuesSupported;
    }

    public String getIssuer() {
        return issuer;
    }

    public URI getJwksUri() {
        return jwksUri;
    }

    public List<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    public URI getRevocationEndpoint() {
        return revocationEndpoint;
    }

    public List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    public List<String> getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    public URI getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public void setAuthorizationEndpoint(final URI authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public void setIdTokenAlgValuesSupported(final List<String> idTokenAlgValuesSupported) {
        this.idTokenAlgValuesSupported = idTokenAlgValuesSupported;
    }

    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    public void setJwksUri(final URI jwksUri) {
        this.jwksUri = jwksUri;
    }

    public void setResponseTypesSupported(final List<String> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

    public void setRevocationEndpoint(final URI revocationEndpoint) {
        this.revocationEndpoint = revocationEndpoint;
    }

    public void setSubjectTypesSupported(final List<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    public void setTokenEndpoint(final URI tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public void setTokenEndpointAuthMethodsSupported(final List<String> tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    public void setUserinfoEndpoint(final URI userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    @Override
    public String toString() {
        return "OpenIDProviderConfigurationResponse [authorizationEndpoint=" + authorizationEndpoint + ", idTokenAlgValuesSupported=" + idTokenAlgValuesSupported + ", issuer=" + issuer + ", jwksUri=" + jwksUri + ", responseTypesSupported=" + responseTypesSupported + ", revocationEndpoint=" + revocationEndpoint + ", subjectTypesSupported=" + subjectTypesSupported + ", tokenEndpoint=" + tokenEndpoint + ", tokenEndpointAuthMethodsSupported=" + tokenEndpointAuthMethodsSupported + "]";
    }
}
