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
    public static boolean isNullOrEmpty(final String s) {
        return s == null || s.trim().length() == 0;
    }

    private Utils() {
    }
}
