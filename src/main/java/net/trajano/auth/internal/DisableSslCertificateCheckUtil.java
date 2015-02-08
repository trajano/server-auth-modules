package net.trajano.auth.internal;

import static javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier;
import static javax.net.ssl.HttpsURLConnection.getDefaultSSLSocketFactory;
import static javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier;
import static javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * Disables SSL certificate checks. Primarily used for doing integration testing
 * against self-signed servers.
 */
public final class DisableSslCertificateCheckUtil {
    /**
     * Flag to indicate that certificate checks are disabled. If this is true,
     * then the process to disable the checks are not executed again.
     */
    private static boolean disabled;

    /**
     * Original hostname verifier, set by {{@link #disableChecks()}.
     */
    private static HostnameVerifier originalHostnameVerifier;

    /**
     * Original SSL Socket factory, set by {{@link #disableChecks()}.
     */
    private static SSLSocketFactory originalSslSocketFactory;

    /**
     * Disable trust checks for SSL connections. Saves the present ones if it is
     * not the disabled ones.
     *
     * @throws GeneralSecurityException
     *             thrown when there is a problem disabling the SSL. Shouldn't
     *             happen unless there is something wrong with the Java
     *             implementation.
     */
    public static void disableChecks() throws GeneralSecurityException {
        if (disabled) {
            return;
        }
        try {
            new URL("https", "0", "/").getContent();
        } catch (final IOException e) {
            // This invocation will always fail, but it will register the
            // default SSL provider to the URL class.
        }
        originalSslSocketFactory = getDefaultSSLSocketFactory();
        originalHostnameVerifier = getDefaultHostnameVerifier();
        final SSLContext context = SSLContext.getInstance("SSLv3");
        final TrustManager[] trustManagerArray = { new NullX509TrustManager() };
        context.init(null, trustManagerArray, null);
        setDefaultSSLSocketFactory(context.getSocketFactory());
        setDefaultHostnameVerifier(new NullHostnameVerifier());
        disabled = true;
    }

    /**
     * This will re-enable the SSL checks after it was disabled by
     * {@link #disableChecks()}.
     */
    public static void reenableChecks() {
        if (!disabled) {
            return;
        }
        setDefaultSSLSocketFactory(originalSslSocketFactory);
        setDefaultHostnameVerifier(originalHostnameVerifier);
        disabled = false;
    }

    /**
     * Prevent instantiation of utility class.
     */
    private DisableSslCertificateCheckUtil() {
    }
}
