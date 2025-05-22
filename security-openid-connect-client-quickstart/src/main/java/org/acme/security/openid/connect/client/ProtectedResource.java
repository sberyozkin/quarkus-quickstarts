package org.acme.security.openid.connect.client;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import io.quarkus.security.Authenticated;
import io.smallrye.mutiny.Uni;


@Path("/protected")
@Authenticated
public class ProtectedResource {

    @GET
    @RolesAllowed("user")
    @Produces("text/plain")
    @Path("userName")
    public Uni<String> userName() {
        return Uni.createFrom().item("hello");
    }
}
