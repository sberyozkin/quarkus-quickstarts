package org.acme;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import io.quarkus.mailer.Mail;
import io.quarkus.mailer.Mailer;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.security.Authenticated;
import io.smallrye.common.annotation.Blocking;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.ext.mail.MailClient;
import io.vertx.ext.mail.MailConfig;
import io.vertx.ext.mail.MailMessage;
import io.vertx.ext.mail.StartTLSOptions;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@Path("/")
public class MailResource {

    @Inject
    Mailer mailer;
    
    @Inject
    Vertx vertx;
    
    @Inject
    AccessTokenCredential accessToken;

    @GET
    @Path("/login")
    @Authenticated
    public String getAccessToken() {
        return accessToken.getToken();
    }
    
    @GET
    @Blocking
    @Path("/mail")
    public void sendEmail() {
        mailer.send(Mail.withText("sberyozkin@gmail.com", "Ahoy from Quarkus", "A simple email sent from a Quarkus application.")
                .setFrom("sberyozkin@gmail.com"));
    }
    
    @GET
    @Blocking
    @Path("/mailnow")
    @Authenticated
    public void sendEmailNow() {
        MailClient mailClient = MailClient.createShared(
                Vertx.vertx(),
                new MailConfig()
                  .setUsername("sberyozkin@gmail.com")
                  .setPassword(accessToken.getToken())
                  .setHostname("smtp.gmail.com")
                  .setStarttls(StartTLSOptions.REQUIRED)
                  .setPort(587));

              MailMessage email = new MailMessage()
                .setFrom("sberyozkin@gmail.com")
                .setTo(Arrays.asList(
                  "sberyozkin@gmail.com"))
                .setSubject("Test email")
                .setText("this is a test email");

              awaitMailClientResponse(mailClient.sendMail(email));
    }

    private <T> T awaitMailClientResponse(Future<T> future) {
        try {
            return future.toCompletionStage().toCompletableFuture().get(120, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


}
