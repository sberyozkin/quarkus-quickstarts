package org.acme.quickstart.tika;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
public class GreetingResourceTest {

    @Test
    public void testHelloEndpoint() {
        given()
          .when().header("Content-Type", "text/plain")
                 .body("hello quarkus")
                 .post("/tika/parse")
          .then()
             .statusCode(200)
             .body(is("hello quarkus"));
    }

}
