package org.acme.software.credentials.verifier;

import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

@ApplicationScoped
public class VerifiablePresentationsProducer {

    @Inject
    RoutingContext routingContext;

    @Produces
    @RequestScoped
    public VerifiablePresentations produce() {
        VerifiablePresentations vp = routingContext.get(
                VerifiablePresentationAuthenticationMechanism.VERIFIABLE_PRESENTATIONS_KEY);
        return vp != null ? vp : new VerifiablePresentations();
    }
}
