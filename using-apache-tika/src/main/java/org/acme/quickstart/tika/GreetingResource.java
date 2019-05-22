package org.acme.quickstart.tika;


import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import io.quarkus.tika.Metadata;
import io.quarkus.tika.TikaContent;

@Path("/parse")
public class GreetingResource {


    @POST
    @Path("/text")
    @Consumes({"text/plain", "application/pdf", "application/vnd.oasis.opendocument.text"})
    @Produces(MediaType.TEXT_PLAIN)
    public String hello(TikaContent content) {
        return content.getText();
    }
    
    @POST
    @Path("/metadata")
    @Consumes({"text/plain", "application/pdf", "application/vnd.oasis.opendocument.text"})
    @Produces(MediaType.TEXT_PLAIN)
    public String hello(Metadata metadata) {
        return metadata.getNames().toString();
    }
}
