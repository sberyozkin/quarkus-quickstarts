package org.acme.quickstart.tika;

import io.quarkus.test.junit.SubstrateTest;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@SubstrateTest
public class NativeGreetingResourceIT extends GreetingResourceTest {

    @Test
    @Disabled
    @Override
    public void testHelloQuarkusPdfFormat() throws Exception {
    }
}
