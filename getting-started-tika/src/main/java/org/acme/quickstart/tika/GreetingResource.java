package org.acme.quickstart.tika;


import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import io.quarkus.tika.runtime.jaxrs.TikaContent;

@Path("/tika")
public class GreetingResource {


    @POST
    @Path("/parse")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public String hello(TikaContent body) {
        return body.getContent();
    }
}
