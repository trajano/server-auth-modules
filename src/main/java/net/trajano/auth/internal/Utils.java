package net.trajano.auth.internal;

/**
 * Utility methods. Normally these would be in a separate JAR file like
 * commons-lang, but to prevent complications during installation such as
 * requiring to install additional JAR files, this class was created.
 *
 * @author Archimedes Trajano
 *
 */
public final class Utils {
    /**
     * Checks if string is null or empty.
     *
     * @param s
     *            string to test
     * @return true if string is null or empty.
     */
    public static boolean isNullOrEmpty(final String s) {
        return s == null || s.trim().length() == 0;
    }

    /**
     * Prevent instantiation of utility class.
     */
    private Utils() {
    }
}
