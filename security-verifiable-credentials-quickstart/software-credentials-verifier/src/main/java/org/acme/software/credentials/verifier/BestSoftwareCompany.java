package org.acme.software.credentials.verifier;

import java.net.URI;
import java.util.List;

import org.acme.software.credentials.utils.QrCodeUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.authlete.sd.SDJWT;

import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata.CredentialConfiguration;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

@Path("/best-software-company")
public class BestSoftwareCompany {

    private static final Logger LOG = Logger.getLogger(BestSoftwareCompany.class);

    @ConfigProperty(name = "wallet.host")
    String walletHost;

    @ConfigProperty(name = "verifier.host")
    String verifierHost;

    @Inject
    Template bestSoftwareCompanyWelcome;

    @Inject
    Template bestSofwareCompanyRequestCredential;

    @Inject
    Template bestSoftwareCompanyPresentationConfirmation;

    @Inject
    OidcCredentialIssuerMetadata oidcCredentialIssuerMetadata;

    @Inject
    RoutingContext rc;

    @Inject
    SecurityIdentity securityIdentity;

    @Inject
    VerifiablePresentations verifiablePresentations;

    @GET
    @Produces("text/html")
    public TemplateInstance applyForSoftwarePosition() {
        return bestSoftwareCompanyWelcome
                .data("credentials", oidcCredentialIssuerMetadata.getCredentialConfigurations().values())
                .data("verifierHost", verifierHost);
    }

    @GET
    @Path("/request-credential")
    @Produces("text/html")
    public TemplateInstance requestCredentialPresentation(@QueryParam("credential-id") String credentialId) {

        JsonObject dcqlQuery = new JsonObject();
        JsonArray creds = new JsonArray();
        dcqlQuery.put("credentials", creds);
        JsonObject credential = new JsonObject();
        credential.put("id", credentialId);
        creds.add(credential);

        String state = rc.get("vp_state");
        String nonce = rc.get("vp_nonce");

        // client_id=software-credentials-verifier
        String presentationUrl = verifierHost + "/best-software-company/presentation";

        String authorizationRequest = "response_mode=direct_post" + "&client_id=redirect_uri:"
                + OidcCommonUtils.urlEncode(presentationUrl) + "&response_uri="
                + OidcCommonUtils.urlEncode(presentationUrl) + "&response_type=" + "vp_token" + "&dcql_query="
                + OidcCommonUtils.urlEncode(dcqlQuery.toString()) + "&scope="
                + oidcCredentialIssuerMetadata.getCredentialConfigurations().get(credentialId).scope() + "&nonce="
                + nonce + "&state=" + state;

        String webLink = walletHost + "/software-credentials-wallet/credential-presentation?" + authorizationRequest;
        // String walletQrCode = QrCodeUtils.generateQrCode("openid4vp://" + authorizationRequest);
        String webLinkQrCode = QrCodeUtils.generateQrCode(webLink);

        return bestSofwareCompanyRequestCredential.data("walletRequestCredential", webLink)
                // .data("base64WalletQrCode", walletQrCode)
                .data("base64WebLinkQrCode", webLinkQrCode)
                .data("credential_metadata",
                        oidcCredentialIssuerMetadata.getCredentialConfigurations().get(credentialId));
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/presentation")
    @Authenticated
    public TemplateInstance presentationConfirmation() {
        String vct = securityIdentity.getAttribute("vct");
        String vctPath = URI.create(vct).getPath();
        String vctValue = vctPath.startsWith("/") ? vctPath.substring(1) : vctPath;

        List<VerifiedPresentation> presentations = verifiablePresentations.getAll();
        SDJWT sdjwt = presentations.get(0).sdjwt();

        return bestSoftwareCompanyPresentationConfirmation.data("disclosures", sdjwt.getDisclosures())
                .data("credential_metadata", getCredentialsMetadata(vctValue));
    }

    private CredentialConfiguration getCredentialsMetadata(String vct) {
        for (CredentialConfiguration cfg : oidcCredentialIssuerMetadata.getCredentialConfigurations().values()) {
            if (cfg.type().equals(vct)) {
                return cfg;
            }
        }
        return null;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/presentation")
    @Authenticated
    public PresentationConfirmation presentation(@Context UriInfo uriInfo) {
        LOG.infof("Credential %s was accepted for %s", securityIdentity.getAttribute("credential"),
                securityIdentity.getPrincipal().getName());
        String vct = securityIdentity.getAttribute("vct");
        String responseCode = rc.get("vp_response_code");

        URI uri = uriInfo.getBaseUriBuilder()
                .path("best-software-company/presentation")
                .queryParam("vct", vct)
                .queryParam("response_code", responseCode)
                .build();

        return new PresentationConfirmation(uri.toString());
    }

    public static record PresentationConfirmation(String redirect_uri) {
    };
}
