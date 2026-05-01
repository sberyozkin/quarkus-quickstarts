package org.acme.software.credentials.issuer;

import java.net.URI;

import org.acme.software.credentials.utils.QrCodeUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.quarkiverse.oidvc.CredentialIssuerMetadata;
import io.quarkus.mailer.Mail;
import io.quarkus.mailer.Mailer;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.IdToken;
import io.quarkus.oidc.OidcProviderClient;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.runtime.OidcProviderClientImpl;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.security.Authenticated;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.UriBuilder;

@Path("/software-credentials-academy")
public class SoftwareCredentialsAcademy {

    private static final Logger LOG = Logger.getLogger(SoftwareCredentialsAcademy.class);

    @ConfigProperty(name = "wallet.host")
    String walletHost;
    
    @ConfigProperty(name = "verifier.host")
    String verifierHost;

    @ConfigProperty(name = "issuer.host")
    String issuerHost;

    @ConfigProperty(name = "keycloak.host")
    String keycloakHost;

    @Inject
    @IdToken
    JsonWebToken idToken;

    @Inject
    AccessTokenCredential accessToken;

    @Inject
    CredentialIssuerMetadata credentialIssuerMetadata;

    @Inject
    OidcProviderClient oidcProviderClient;

    @Inject
    Template softwareCredentialsAcademy;

    @Inject
    Template softwareCredentialsAcademyOffer;
    
    @Inject
    Template softwareCredentialsAcademyOffers;

    @Inject
    Mailer mailer;

    @GET
    @Produces("text/html")
    public TemplateInstance academy() {
        return softwareCredentialsAcademy.data("issuerHost", issuerHost);
    }
    
    
    @GET
    @Produces("text/html")
    @Path("/dashboard")
    @Authenticated
    public TemplateInstance getCredentialConfigurations() {
        return softwareCredentialsAcademyOffers
                .data("credentials", credentialIssuerMetadata.getCredentialConfigurations().values())
                .data("issuerHost", issuerHost)
                .data("verifierHost", verifierHost)
                .data("name", getUserFirstName());
    }

    @GET
    @Path("/credential-offer")
    @Authenticated
    @Produces("text/html")
    public TemplateInstance getCredentialOffer(@QueryParam("credential-id") String credentialId) {

        String credentialOfferQuery = getCredentialOfferQuery(credentialId);

        String walletWebLink = walletHost + "/software-credentials-wallet/credential-offer?" + credentialOfferQuery;
        // String walletQrCode = QrCodeUtils.generateQrCode("openid-credential-offer://" + credentialOfferQuery);
        String webLinkQrCode = QrCodeUtils.generateQrCode(walletWebLink);
        return softwareCredentialsAcademyOffer.data("walletCredentialOffer", walletWebLink)
                // .data("base64WalletQrCode", walletQrCode)
                .data("base64WebLinkQrCode", webLinkQrCode)
                .data("credential_metadata",
                        credentialIssuerMetadata.getCredentialConfigurations().get(credentialId));
    }

    // TODO: update to return Uni
    private String getCredentialOfferQuery(String credentialId) {

        String credentialOfferUri = getCredentialOfferUri(credentialId);

        // return "credential_offer_uri=" +
        // OidcCommonUtils.urlEncode(credentialOfferUri);
        HttpResponse<Buffer> response = getWebClient().getAbs(credentialOfferUri)
                .bearerTokenAuthentication(accessToken.getToken()).putHeader("Accept", "application/json").send()
                .await().indefinitely();

        if (response.statusCode() != 200) {
            LOG.errorf("Credential offer request failed, status: %d, error: %s", response.statusCode(),
                    response.bodyAsString());
            return null;
        }

        JsonObject offer = response.bodyAsJsonObject();
        JsonObject grants = offer.getJsonObject("grants");
        JsonObject preAuthorizedGrant = grants.getJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code");

        JsonObject txCode = new JsonObject();
        txCode.put("length", 4);
        txCode.put("input_mode", "numeric");
        txCode.put("description", "Please provide the one-time code that was sent via e-mail");

        preAuthorizedGrant.put("tx_code", txCode);
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthorizedGrant);

        mailer.send(Mail.withText(idToken.getClaim("email"),
                String.format("Transaction code to complete %s offer", credentialId),
                String.valueOf((int) (Math.random() * 9000) + 1000)));

        return "credential_offer=" + OidcCommonUtils.urlEncode(offer.toString());
    }

    // TODO: update to return Uni
    private String getCredentialOfferUri(String credentialId) {

        String credOfferEndpoint = credentialIssuerMetadata.getAuthServerUrl()
                + "/protocol/oid4vc/credential-offer-uri?credential_configuration_id=" + credentialId;

        HttpResponse<Buffer> credOfferUriResponse = getWebClient().getAbs(credOfferEndpoint)
                .bearerTokenAuthentication(accessToken.getToken()).putHeader("Accept", "application/json").send()
                .await().indefinitely();

        JsonObject credOfferUriJson = credOfferUriResponse.bodyAsJsonObject();

        URI credOfferIssuerUri = URI.create(credOfferUriJson.getString("issuer"));
        String credentialOfferUri = UriBuilder.fromUri(keycloakHost).path(credOfferIssuerUri.getRawPath())
                .path(credOfferUriJson.getString("nonce")).build().toString();

        // return "credential_offer_uri=" +
        // OidcCommonUtils.urlEncode(credentialOfferUri);
        return credentialOfferUri;
    }

    // The following 2 methods are here to emulate the case when the issuer and its
    // authorization server are not co-located,
    // and for the wallet not to assume it

    @GET
    @Path(".well-known/openid-credential-issuer")
    @Produces("application/json")
    public String getCredentialMetadata() {
        JsonObject json = new JsonObject(credentialIssuerMetadata.getMetadata().toString());
        json.put(CredentialIssuerMetadata.CREDENTIAL_ENDPOINT,
                issuerHost + "/software-credentials-academy/credential_endpoint");
        return json.toString();
    }

    @POST
    @Path("credential_endpoint")
    @Produces("application/json")
    @Consumes("application/json")
    public Uni<String> credentialEndpoint(@HeaderParam("Authorization") String authorization, String json) {
        LOG.infof("Proxying a credential request %s to %s", json, credentialIssuerMetadata.getCredentialEndpoint());
        return getWebClient().postAbs(credentialIssuerMetadata.getCredentialEndpoint())
                .putHeader("Authorization", authorization).putHeader("Content-Type", "application/json")
                .putHeader("Accept", "application/json").send().onItem().transform(httpResp -> httpResp.bodyAsString());
    }
    
    private String getUserFirstName() {
        String firstName = idToken.getClaim("given_name");
        return firstName == null ? idToken.getName() : firstName;
    }
    
    private WebClient getWebClient() {
        return ((OidcProviderClientImpl)io.quarkus.arc.ClientProxy.unwrap(oidcProviderClient)).getWebClient();
    }
}
