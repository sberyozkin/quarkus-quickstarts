package org.acme.software.credentials.wallet;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.acme.software.credentials.wallet.VerifiableCredentialEntity.CredentialId;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;

import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.IdToken;
import io.quarkus.oidc.OidcProviderClient;
import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata.CredentialConfiguration;
import io.quarkus.oidcvc.VerifiableCredential;
import io.quarkus.oidcvc.VerifiablePresentation;
import io.quarkus.oidcvc.runtime.OidcVcUtils;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.security.Authenticated;
import io.smallrye.jwt.build.Jwt;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mutiny.core.MultiMap;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

@Path("/software-credentials-wallet")
public class SoftwareCredentialsWallet {

    private static final Logger LOG = Logger.getLogger(SoftwareCredentialsWallet.class);

    @ConfigProperty(name = "wallet.host")
    String walletHost;

    @ConfigProperty(name = "issuer.host")
    String issuerHost;

    @ConfigProperty(name = "verifier.host")
    String verifierHost;

    @Inject
    @IdToken
    JsonWebToken idToken;

    @Inject
    AccessTokenCredential accessToken;

    @Inject
    OidcCredentialIssuerMetadata oidcCredentialIssuerMetadata;

    @Inject
    Template walletLogin;
    @Inject
    Template walletCredentials;
    @Inject
    Template walletCredential;
    @Inject
    Template walletAcceptCredentialOffer;
    @Inject
    Template walletReplaceCredential;
    @Inject
    Template walletPresentCredential;
    @Inject
    Template walletCredentialPresentationAgreement;
    @Inject
    Template walletCredentialPresentationConfirmation;

    @Inject
    VerifiableCredential verifiableCredential;

    @Inject
    RoutingContext rc;

    @Inject
    OidcProviderClient oidcProviderClient;

    @Inject
    OidcClient oidcClient;

    @GET
    @Produces("text/html")
    public TemplateInstance wallet() {
        return walletLogin.data("walletHost", walletHost).data("issuerHost", issuerHost).data("verifierHost",
                verifierHost);
    }

    @GET
    @Path("/dashboard")
    @Produces("text/html")
    @Authenticated
    @Transactional
    public TemplateInstance getSavedCredentials() {
        List<CredentialConfiguration> credConfigs = List.of();
        List<String> savedCreds = findSavedCredentials();
        if (!savedCreds.isEmpty()) {
            credConfigs = oidcCredentialIssuerMetadata.getCredentialConfigurations().values().stream()
                    .filter(c -> savedCreds.contains(c.id())).toList();
        }

        return walletCredentials.data("credentials", credConfigs).data("name", getUserFirstName())
                .data("walletHost", walletHost).data("issuerHost", issuerHost).data("verifierHost", verifierHost);
    }

    @GET
    @Path("/credential")
    @Produces("text/html")
    @Authenticated
    @Transactional
    public TemplateInstance getSavedCredentialDisclosures(@QueryParam("credentialId") String credentialId) {
        VerifiableCredential vc = findCredential(credentialId);
        CredentialConfiguration cred = oidcCredentialIssuerMetadata.getCredentialConfigurations().get(credentialId);
        return walletCredential.data("disclosures", vc.getDisclosures()).data("credential_metadata", cred);
    }

    @GET
    @Path("/credential-offer")
    @Produces("text/html")
    @Authenticated
    @Transactional
    public TemplateInstance credentialOffer(@QueryParam("credential_offer") String credentialOffer,
            @Context UriInfo uriInfo) {

        JsonObject offer = new JsonObject(credentialOffer);

        JsonArray credentialConfigIds = offer.getJsonArray("credential_configuration_ids");
        String credentialId = credentialConfigIds.getString(0);

        CredentialConfiguration cred = oidcCredentialIssuerMetadata.getCredentialConfigurations().get(credentialId);
        VerifiableCredential vc = findCredential(credentialId);

        // TODO: ${keycloak.url}/realms/some-realm/.well-known/openid-credential-issuer
        // may or may not return a `display` JSON object
        // SoftwareCredentialIssuer should support
        // `.well-known/openid-credential-issuer` and augment Keycloak's Credential
        // Issuer metadata
        // with its own `display`, so that the wallet could ask a user to accept a
        // credential offer from a named issuer, with the name
        // retrieved from `display`. For now, we hardcode it to `Software Credentials
        // Issuer`.

        if (vc == null) {
            return walletAcceptCredentialOffer.data("name", getUserFirstName())
                    .data("credential_offer", credentialOffer).data("credential_metadata", cred)
                    .data("credential_issuer", "Software Credentials Academy");
        } else {
            return walletReplaceCredential.data("name", getUserFirstName()).data("credential_offer", credentialOffer)
                    .data("credential_metadata", cred).data("credential_issuer", "Software Credentials Academy");
        }
    }

    @POST
    @Path("/credential-offer-completion")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("text/html")
    @Authenticated
    @Transactional
    public Response credentialOfferCompletion(@FormParam("credential_offer") String credentialOffer,
            @FormParam("tx_code") String transactionCode, @Context UriInfo uriInfo) {

        VerifiableCredential vc = getCredentialOfferFromValue(credentialOffer, transactionCode);

        persistVerifiableCredential(vc);

        URI uri = uriInfo.getBaseUriBuilder().path("software-credentials-wallet").path("dashboard").build();
        return Response.seeOther(uri).build();
    }

    @POST
    @Path("/credential-offer-replace")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("text/html")
    @Authenticated
    @Transactional
    public Response credentialOfferReplace(@FormParam("credential_offer") String credentialOffer,
            String transactionCode, @Context UriInfo uriInfo) {

        VerifiableCredential offer = getCredentialOfferFromValue(credentialOffer, transactionCode);
        VerifiableCredentialEntity.deleteById(new CredentialId(idToken.getName(), offer.getCredentialId()));
        VerifiableCredentialEntity.flush();
        persistVerifiableCredential(offer);
        URI uri = uriInfo.getBaseUriBuilder().path("software-credentials-wallet").path("dashboard").build();
        return Response.seeOther(uri).build();
    }

    @POST
    @Path("/remove-credential")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("text/html")
    @Authenticated
    @Transactional
    public Response removeCredential(@FormParam("credential_id") String credentialId, @Context UriInfo uriInfo) {
        VerifiableCredentialEntity.deleteById(new CredentialId(idToken.getName(), credentialId));
        VerifiableCredentialEntity.flush();
        URI uri = uriInfo.getBaseUriBuilder().path("software-credentials-wallet").path("dashboard").build();
        return Response.seeOther(uri).build();
    }

    @GET
    @Path("/credential-presentation")
    @Produces("text/html")
    @Authenticated
    @Transactional
    public Response credentialPresentation(@QueryParam("response_uri") String credentialResponseUri,
            @QueryParam("client_id") String clientId,
            @QueryParam("dcql_query") String dcqlQuery, @QueryParam("state") String state,
            @QueryParam("nonce") String nonce, @Context UriInfo uriInfo) {

        JsonObject dcql = new JsonObject(dcqlQuery);

        JsonArray credentials = dcql.getJsonArray("credentials");
        JsonObject credential = credentials.getJsonObject(0);
        String credentialId = credential.getString("id");

        VerifiableCredential vc = findCredential(credentialId);
        if (vc == null) {
            // TODO: get the name of the verifier from the dcql query or other presentation
            // request parameter
            CredentialConfiguration cred = oidcCredentialIssuerMetadata.getCredentialConfigurations().get(credentialId);
            TemplateInstance templateInstance = walletCredentialPresentationAgreement.data("name", getUserFirstName())
                    .data("dcql_query", dcqlQuery).data("state", state).data("nonce", nonce)
                    .data("client_id", clientId)
                    .data("response_uri", credentialResponseUri)
                    .data("credential_metadata", cred).data("credential_verifier", "Best Software Company");
            return Response.ok(templateInstance).build();
        }

        return Response.ok(getCredentialDisclosures(vc, credentialResponseUri, dcqlQuery, state, nonce, clientId)).build();
    }

    @POST
    @Path("/credential-presentation-agreement")
    @Produces("text/html")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Authenticated
    public Response credentialPresentationAgreement(@FormParam("response_uri") String credentialResponseUri,
            @FormParam("client_id") String clientId,
            @FormParam("dcql_query") String dcqlQuery, @FormParam("state") String state,
            @FormParam("nonce") String nonce, @Context UriInfo uriInfo) {

        JsonObject dcql = new JsonObject(dcqlQuery);

        JsonArray credentials = dcql.getJsonArray("credentials");
        JsonObject credential = credentials.getJsonObject(0);
        String credentialId = credential.getString("id");

        URI uri = uriInfo.getBaseUriBuilder().path("software-credentials-wallet")
                .path("credential-presentation-completion").queryParam("response_uri", credentialResponseUri)
                .queryParam("client_id", clientId)
                .queryParam("state", state).queryParam("nonce", nonce)
                .queryParam("dcql_query", OidcCommonUtils.urlEncode(dcqlQuery))
                .queryParam("id", credentialId).build();
        return Response.seeOther(uri).build();

    }

    @GET
    @Path("/credential-presentation-completion")
    @Produces("text/html")
    @Authenticated
    @Transactional
    public TemplateInstance completeCredentialPresentation(@QueryParam("response_uri") String credentialResponseUri,
            @QueryParam("client_id") String clientId,
            @QueryParam("dcql_query") String dcqlQuery, @QueryParam("state") String state,
            @QueryParam("nonce") String nonce) {
        persistVerifiableCredential(verifiableCredential);
        return getCredentialDisclosures(verifiableCredential, credentialResponseUri, dcqlQuery, state, nonce, clientId);
    }

    private TemplateInstance getCredentialDisclosures(VerifiableCredential vc, String credentialResponseUri,
            String dcqlQuery, String state, String nonce, String clientId) {
        return walletPresentCredential.data("credential_verifier", "Best Software Company")
                .data("dcql_query", dcqlQuery).data("state", state).data("nonce", nonce)
                .data("client_id", clientId)
                .data("response_uri", credentialResponseUri)
                .data("credential_metadata",
                        oidcCredentialIssuerMetadata.getCredentialConfigurations().get(vc.getCredentialId()))
                .data("disclosures", vc.getDisclosures());
    }

    private VerifiableCredential getCredentialOfferFromValue(String credentialOffer, String transactionCode) {
        LOG.infof("Credential offer: %s", credentialOffer);

        JsonObject offer = new JsonObject(credentialOffer);

        JsonArray credentialConfigIds = offer.getJsonArray("credential_configuration_ids");
        String credentialId = credentialConfigIds.getString(0);

        JsonObject grants = offer.getJsonObject("grants");
        JsonObject preAuthorizedGrant = grants.getJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        String preAuthorizedCode = preAuthorizedGrant.getString("pre-authorized_code");
        // TODO: update to return Uni
        String credentialToken = oidcClient
                .getTokens(Map.of("pre-authorized_code", preAuthorizedCode, "tx_code", transactionCode)).await()
                .indefinitely().getAccessToken();

        return OidcVcUtils.getVerifiableCredential(rc, credentialToken, oidcCredentialIssuerMetadata, credentialId,
                oidcProviderClient.getWebClient()).await().indefinitely();
    }

    @POST
    @Path("/credentials")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Authenticated
    @Produces("text/plain")
    public Response presentCredential(
            @FormParam("response_uri") String credentialResponseUri,
            @FormParam("client_id") String clientId,
            @FormParam("dcql_query") String dcqlQuery, @FormParam("state") String state,
            @FormParam("nonce") String nonce,
            @FormParam("credentialId") String credentialId, @FormParam("disclosure") Set<String> approvedDisclosures)
            throws Exception {

        VerifiableCredential vc = findCredential(credentialId);

        LOG.infof("Presenting the credential to %s", credentialResponseUri);

        String vp = new VerifiablePresentation(vc, approvedDisclosures).getVerifiablePresentationString();

        vp = addKeyBinding(vp, clientId, nonce, vc.getKeyBindingPrivateKey());

        MultiMap presentationForm = MultiMap.caseInsensitiveMultiMap();
        presentationForm.add("vp_token", vp);
        presentationForm.add("state", state);

        JsonObject json = oidcProviderClient.getWebClient().postAbs(credentialResponseUri)
                .putHeader("Content-Type", "application/x-www-form-urlencoded").putHeader("Accept", "application/json")
                .sendForm(presentationForm).await().indefinitely().bodyAsJsonObject();

        String redirectUri = json.getString("redirect_uri");

        if (redirectUri != null) {
            return Response.seeOther(URI.create(redirectUri)).build();
        }

        return Response.ok(walletCredentialPresentationConfirmation
                .data("credential_metadata",
                        oidcCredentialIssuerMetadata.getCredentialConfigurations().get(credentialId))
                .data("credential_verifier", "Best Software Company")).build();
    }

    private void persistVerifiableCredential(VerifiableCredential vc) {

        LOG.infof("Verifiable Credential %s with sdjwt %s for the user %s is being persisted", vc.getCredentialId(),
                vc.getSdJwt(), idToken.getName());

        VerifiableCredentialEntity entity = new VerifiableCredentialEntity(idToken.getName(), vc.getCredentialId(),
                vc.getSdJwt(), vc.getKeyBindingPrivateKey());
        entity.persistAndFlush();
    }

    private VerifiableCredential findCredential(String credentialId) {

        VerifiableCredentialEntity vce = findCredentialEntity(credentialId);
        if (vce != null) {
            return new VerifiableCredential(vce.id.credentialId(), vce.vc, vce.privateKey);
        }
        return null;
    }

    private VerifiableCredentialEntity findCredentialEntity(String credentialId) {

        CredentialId id = new CredentialId(idToken.getName(), credentialId);
        VerifiableCredentialEntity vce = VerifiableCredentialEntity.findById(id);
        if (vce != null) {
            LOG.infof("Verifiable Credential %s with sdjwt %s for the user %s is found", credentialId, vce.vc,
                    idToken.getName());
        }
        return vce;
    }

    private List<String> findSavedCredentials() {

        List<VerifiableCredentialEntity> vcs = VerifiableCredentialEntity.listAll();
        return vcs.stream().filter(vc -> vc.id.name().equals(idToken.getName())).map(vc -> vc.id.credentialId())
                .toList();

    }

    private String getUserFirstName() {
        String firstName = idToken.getClaim("given_name");
        return firstName == null ? idToken.getName() : firstName;
    }

    private String addKeyBinding(String vp, String verifierAud, String nonce, String keyBindingPrivateKey) {
        try {
            EllipticCurveJsonWebKey jwk = (EllipticCurveJsonWebKey) JsonWebKey.Factory
                    .newJwk(JsonUtil.parseJson(keyBindingPrivateKey));

            byte[] sdHashBytes = OidcUtils.getSha256Digest(vp.getBytes(StandardCharsets.US_ASCII));
            String sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(sdHashBytes);

            String jwt = Jwt.audience(verifierAud).claim("sd_hash", sdHash).claim("nonce", nonce)
                    .jws().type("kb+jwt").sign(jwk.getPrivateKey());

            return vp + jwt;

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
