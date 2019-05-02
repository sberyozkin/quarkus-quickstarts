package org.acme.quickstart.tika;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
public class GreetingResourceTest {

    @Test
    public void testHelloQuarkusTextFormat() throws Exception {
        doTestHelloQuarkus("text/plain", "txt");
    }

    @Test
    public void testHelloQuarkusOdtFormat() throws Exception {
        doTestHelloQuarkus("application/vnd.oasis.opendocument.text", "odt");
    }

    @Test
    public void testHelloQuarkusPdfFormat() throws Exception {
        doTestHelloQuarkus("application/pdf", "pdf");
    }

    private void doTestHelloQuarkus(String contentType, String extension) throws Exception {
        given()
          .when().header("Content-Type", contentType)
                 .body(readQuarkusFile("quarkus." + extension))
                 .post("/tika/parse")
          .then()
             .statusCode(200)
             .body(is("Hello Quarkus"));
    }

    private byte[] readQuarkusFile(String fileName) throws Exception {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(fileName)) {
            return readBytes(is);    
        }
    }

    static byte[] readBytes(InputStream is) throws Exception {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int len;
        while ((len = is.read(buffer)) != -1) {
            os.write(buffer, 0, len);
        }
        return os.toByteArray();
    }

}
