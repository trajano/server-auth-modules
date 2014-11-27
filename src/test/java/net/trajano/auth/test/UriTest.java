package net.trajano.auth.test;

import java.net.URI;

import org.junit.Test;

public class UriTest {

    @Test
    public void testUri() {

        final URI uri = URI.create("https://angel.stone.co:8181/angelstone/1.0/search/10000000-0000-0000-0000-000000000000?q=angelstone");
        System.out.println(uri.getSchemeSpecificPart());
        System.out.println(uri.getPath());
        System.out.println(uri.getPath() + "?" + uri.getQuery());
        System.out.println(uri.getPath()
                .substring("/angelstone".length()) + "?" + uri.getQuery());
    }
}
