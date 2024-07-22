package org.acme.getting.started;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.wildfly.security.x500.cert.acme.AcmeAccount;
import org.wildfly.security.x500.cert.acme.AcmeChallenge;
import org.wildfly.security.x500.cert.acme.AcmeClientSpi;
import org.wildfly.security.x500.cert.acme.AcmeException;

import io.quarkus.logging.Log;
import io.smallrye.common.constraint.Assert;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

public class AcmeClient extends AcmeClientSpi {

    private static final String TOKEN_REGEX = "[A-Za-z0-9_-]+";

    private final String challengeUrl;
    private final String certsUrl;
    private final WebClientOptions options;
    private final Vertx vertx;

    Optional<String> managementUser;
    Optional<String> managementPassword;
    Optional<String> managementKey;

    private final WebClient managementClient;

    public AcmeClient(String managementUrl, 
                      Optional<String> managementUser,
                      Optional<String> managementPassword,
                      Optional<String> managementKey) {
        this.vertx = Vertx.vertx();
        Log.info("Creating AcmeClient with " + managementUrl);
        
        Log.info("Initializing management WebClient");
        var url = managementUrl;
        // It will need to become configurable to support mTLS, etc
        options = new WebClientOptions();
        options.setMaxPoolSize(20);
        options.getPoolOptions().setEventLoopSize(4).setHttp1MaxSize(20).setHttp2MaxSize(20);
        if (url.startsWith("https://")) {
            options.setSsl(true).setTrustAll(true).setVerifyHost(false);
        }
        this.managementClient = WebClient.create(vertx, options);
        if (url.endsWith("/q/lets-encrypt")) {
            this.challengeUrl = url + "/challenge";
            this.certsUrl = url + "/certs";
        } else {
            this.challengeUrl = url + "/q/lets-encrypt/challenge";
            this.certsUrl = url + "/q/lets-encrypt/certs";
        }
        this.managementUser = managementUser;
        this.managementPassword = managementPassword;
        this.managementKey = managementKey;
    }

    public void checkReadiness() {
        
        // Check status
        Log.info("Checking management challenge endpoint status using " + challengeUrl);
        HttpRequest<Buffer> request = managementClient.getAbs(challengeUrl);
        addKeyAndUser(request);
        try {
            HttpResponse<Buffer> response = await(request.send());
            int status = response.statusCode();
            switch (status) {
                case 200 ->
                        Log.info("Let's Encrypt challenge endpoint is ready, and the challenge is already configured");
                case 204 -> Log.info("Let's Encrypt challenge endpoint is ready, the challenge can be configured");
                case 404 ->
                        Log.warn("Let's Encrypt challenge endpoint is not found, make sure `quarkus.tls.lets-encrypt.enabled` is set to `true`");
                default -> Log.warn("Unexpected status code from the management challenge endpoint: " + status);
            }
        } catch (Exception e) {
            throw new RuntimeException("Quarkus management endpoint is not ready, make sure the Quarkus application is running", e);
        }
        
    }

    @Override
    public AcmeChallenge proveIdentifierControl(AcmeAccount account, List<AcmeChallenge> challenges)
            throws AcmeException {
        Log.info("Prepare to handle challenges");

        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("challenges", challenges);
        AcmeChallenge selectedChallenge = null;
        for (AcmeChallenge challenge : challenges) {
            if (challenge.getType() == AcmeChallenge.Type.HTTP_01) {
                Log.info("HTTP 01 challenge is selected");
                selectedChallenge = challenge;
                break;
            }
        }
        if (selectedChallenge == null) {
            throw new RuntimeException("Missing certificate authority challenge");
        }

        // ensure the token is valid before proceeding
        String token = selectedChallenge.getToken();
        if (!token.matches(TOKEN_REGEX)) {
            throw new RuntimeException("Invalid certificate authority challenge");
        }

        Log.infof("Preparing a selected challenge content for token %s", token);
        String selectedChallengeString = selectedChallenge.getKeyAuthorization(account);

        // respond to the http challenge
        if (managementClient != null) {
            JsonObject challenge = new JsonObject().put("challenge-resource", token).put("challenge-content", selectedChallengeString);
            HttpRequest<Buffer> request = managementClient.getAbs(challengeUrl);
            request.addQueryParam("challenge-resource", token).addQueryParam("challenge-content", selectedChallengeString);
            addKeyAndUser(request);
            Log.infof("Sending token %s and challenge content %s to the management challenge endpoint %s : %s", token, selectedChallengeString, challengeUrl, challenge.encode());

            HttpResponse<Buffer> response = await(request.send());
            System.out.println("POSTED!");
            if (response.statusCode() != 204) {
                Log.error("Failed to upload challenge content to the management challenge endpoint, status code: " + response.statusCode());
                throw new RuntimeException("Failed to respond to certificate authority challenge");
            }
        }
        return selectedChallenge;
    }

    @Override
    public void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException {
        Log.infof("Performing cleanup after the challenge");

        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("challenge", challenge);
        // ensure the token is valid before proceeding
        String token = challenge.getToken();
        if (!token.matches(TOKEN_REGEX)) {
            throw new RuntimeException("Invalid certificate authority challenge");
        }

        if (managementClient != null) {
            Log.infof("Requesting the management challenge endpoint to delete a challenge resource %s", token);

            HttpRequest<Buffer> request = managementClient.deleteAbs(challengeUrl);
            addKeyAndUser(request);
            HttpResponse<Buffer> response = await(request.send());
            if (response.statusCode() != 204) {
                throw new RuntimeException("Failed to clear challenge content in the Quarkus management endpoint");
            }
        }
    }

    public void certificateChainAndKeyAreReady() {
        if (managementClient != null) {
            Log.info("Notifying management challenge endpoint that a new certificate chain and private key are ready");
            HttpRequest<Buffer> request = managementClient.postAbs(certsUrl);
            addKeyAndUser(request);
            HttpResponse<Buffer> response = await(request.send());
            if (response.statusCode() != 204) {
                throw new RuntimeException("Failed to notify the Quarkus management endpoint");
            }
        }
    }

    private HttpRequest<Buffer> addKeyAndUser(HttpRequest<Buffer> request) {
        managementKey.ifPresent(s -> request.addQueryParam("key", s));
        if (managementUser.isPresent() && managementPassword.isPresent()) {
            request.basicAuthentication(managementUser.get(), managementPassword.get());
        }
        return request;
    }

    private <T> T await(Future<T> future) {
        try {
            return future.toCompletionStage().toCompletableFuture().get(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
