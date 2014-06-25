package net.trajano.auth.internal;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * OAuth token.
 *
 * @author Archimedes Trajano
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class OAuthToken {
    /**
     * Access token.
     */
    @XmlElement(name = "access_token")
    private String accessToken;

    /**
     * Expires in. This is the time in seconds since 1970-01-01T00:00:00Z.
     */
    @XmlElement(name = "expires_in")
    private int expiresIn;

    /**
     * ID Token. Used to contain the user's identification.
     */
    @XmlElement(name = "id_token")
    private String idToken;

    /**
     * Token type.
     */
    @XmlElement(name = "token_type")
    private String tokenType;

    public String getAccessToken() {
        return accessToken;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public String getIdToken() {
        return idToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    /**
     * Checks whether the token is expired.
     *
     * @return token is expired.
     */
    @XmlTransient
    public boolean isExpired() {
        return System.currentTimeMillis() > expiresIn * 1000L;
    }

    public void setAccessToken(final String accessToken) {
        this.accessToken = accessToken;
    }

    public void setExpiresIn(final int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public void setIdToken(final String idToken) {
        this.idToken = idToken;
    }

    public void setTokenType(final String tokenType) {
        this.tokenType = tokenType;
    }

    @Override
    public String toString() {
        return "TokenResponse [accessToken=" + accessToken + ", expiresIn="
                + expiresIn + ", idToken=" + idToken + ", tokenType="
                + tokenType + "]";
    }
}
