package org.acme.security.openid.vc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.Cookie;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class OpenidVcTest {

    @Test
    public void testVerifiableCredential() throws IOException {
        try (final WebClient webClient = createWebClient()) {
            HtmlPage page = webClient.getPage("http://localhost:8081/index.html");

            
            
            webClient.getCookieManager().clearCookies();
        }
    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();

        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        // Setting the cache size to zero as webClient by default can store cached request,
        // which causing the `testTokenTimeoutLogout` fail as the session cookie is not changed
        webClient.getCache().setMaxSize(0);

        return webClient;
    }

}
