package org.acme.getting.started;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.jboss.logging.Logger;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

@Path("/.well-known/acme-challenge/")
public class AcmeChallengeResource {
    private static Logger LOG = Logger.getLogger(AcmeChallengeResource.class);
    private static final String ACME_CHALLENGE_PREFIX = "/.well-known/acme-challenge/";

    @GET
    @Path("{token:.*}")
    public String getResource(@PathParam("token") String token) {
        LOG.infof("Serving token %s resource", token);
        
        String responseFilePath = "acme" + ACME_CHALLENGE_PREFIX + token;

        try (FileInputStream fis = new FileInputStream(responseFilePath)) {
            return new String(fis.readAllBytes(), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new RuntimeException("Unable to read the resource");
        }
    }

}
