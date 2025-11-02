package org.acme.software.credentials.verifier;

import java.net.URI;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.acme.software.credentials.utils.QrCodeUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.common.runtime.OidcCommonUtils;
import io.quarkus.oidc.runtime.OidcProvider;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.oidc.runtime.TenantConfigContext;
import io.quarkus.oidc.runtime.TokenVerificationResult;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata;
import io.quarkus.oidcvc.OidcCredentialIssuerMetadata.CredentialConfiguration;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.security.Authenticated;
import io.quarkus.security.AuthenticationFailedException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

@Path("/best-software-company")
public class BestSoftwareCompany {

    private static final Logger LOG = Logger.getLogger(BestSoftwareCompany.class);

    private ConcurrentHashMap<String, SDJWT> vps = new ConcurrentHashMap<>();

    @ConfigProperty(name = "wallet.host")
    String walletHost;

    @ConfigProperty(name = "verifier.host")
    String verifierHost;

    @Inject
    JsonWebToken principal;

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

        String state = UUID.randomUUID().toString();
        // Use Keycloak Credential Nonce endpoint ?
        String nonce = UUID.randomUUID().toString();

        // client_id=software-credentials-verifier
        String presentationUrl = verifierHost + "/best-software-company/presentation";

        String authorizationRequest = "response_mode=direct_post" + "&client_id=redirect_uri:"
                + OidcCommonUtils.urlEncode(presentationUrl) + "&response_uri="
                + OidcCommonUtils.urlEncode(presentationUrl) + "&response_type=" + "vp_token" + "&dcql_query="
                + OidcCommonUtils.urlEncode(dcqlQuery.toString()) + "&scope="
                + oidcCredentialIssuerMetadata.getCredentialConfigurations().get(credentialId).scope() + "&nonce="
                + nonce + "&state=" + state;

        // and have a state cookie

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
    @Path("/presentation/{state}")
    public TemplateInstance presentationConfirmation(@PathParam("state") String state, @QueryParam("vct") String vct) {

        // TODO: avoid a workaround related to the fact that vct may not be equal to the
        // credential id
        String vctPath = URI.create(vct).getPath();
        String vctValue = vctPath.startsWith("/") ? vctPath.substring(1) : vctPath;

        SDJWT sdjwt = vps.get(state);
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

    @Authenticated
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/presentation")
    public PresentationConfirmation presentation(@FormParam("vp_token") String vpToken,
            @FormParam("state") String state, @Context UriInfo uriInfo) {
        LOG.infof("Credential %s was accepted for %s", vpToken, principal.getName());

        SDJWT sdJwt = SDJWT.parse(vpToken);
        verifyKeyBinding(sdJwt, vpToken);

        JsonObject credJwt = OidcUtils.decodeJwtContent(sdJwt.getCredentialJwt());
        String vct = credJwt.getString("vct");

        vps.put(state, sdJwt);

        URI uri = uriInfo.getRequestUriBuilder().path(state).queryParam("vct", vct).build();

        return new PresentationConfirmation(uri.toString());
    }

    private void verifyKeyBinding(SDJWT sdJwt, String vpToken) {
        final TenantConfigContext configContext = rc.get(TenantConfigContext.class.getName());

        // Verify the credential JWT itself
        TokenVerificationResult credentialJwtResult = verifyCredentialJwt(configContext.provider(),
                configContext.getOidcTenantConfig(), sdJwt.getCredentialJwt());

        JsonObject credentialClaims = credentialJwtResult.getLocalVerificationResult();
        JsonArray sdArray = credentialClaims.getJsonArray("_sd");
        if (sdArray == null) {
            LOG.warn("Credential JWT does not contain _sd array");
            throw new AuthenticationFailedException();
        }
        for (Disclosure disclosure : sdJwt.getDisclosures()) {
            if (!sdArray.contains(disclosure.digest())) {
                LOG.warnf("Disclosure digest %s not found in credential JWT _sd array", disclosure.digest());
                throw new AuthenticationFailedException();
            }
        }

        // Verify key binding
        JsonObject cnf = credentialJwtResult.getLocalVerificationResult().getJsonObject("cnf");
        if (cnf == null) {
            LOG.warn("Confirmation is missing");
            throw new AuthenticationFailedException();
        }
        JsonObject jwkProof = cnf.getJsonObject("jwk");
        if (jwkProof == null) {
            LOG.warn("JWK proof is missing");
            throw new AuthenticationFailedException();
        }

        PublicJsonWebKey publicJsonWebKey = null;
        try {
            publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(jwkProof.getMap());
        } catch (JoseException ex) {
            LOG.warn("JWK proof does not represent a valid JWK key");
            throw new AuthenticationFailedException();
        }

        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, "ES256"));
            jws.setCompactSerialization(sdJwt.getBindingJwt());
            jws.setKey(publicJsonWebKey.getPublicKey());
            if (!jws.verifySignature()) {
                LOG.warn("Key binding token token signature is invalid");
                throw new AuthenticationFailedException();
            }
        } catch (JoseException ex) {
            LOG.warn("Key binding token signature can not be verified");
            throw new AuthenticationFailedException();
        }

        JsonObject bindingClaims = OidcUtils.decodeJwtContent(sdJwt.getBindingJwt());
        String sdHashClaim = bindingClaims.getString("sd_hash");
        if (sdHashClaim == null) {
            LOG.warn("Key binding JWT does not contain sd_hash claim");
            throw new AuthenticationFailedException();
        }
        String expectedSdHash = sdJwt.getSDHash();
        if (!sdHashClaim.equals(expectedSdHash)) {
            LOG.warn("Key binding JWT sd_hash does not match the SD-JWT hash");
            throw new AuthenticationFailedException();
        }
    }

    private static TokenVerificationResult verifyCredentialJwt(OidcProvider provider, OidcTenantConfig oidcConfig,
            String credentialJwt) {
        try {
            final boolean enforceExpClaim = oidcConfig.token().age().isEmpty();
            return provider.verifyJwtToken(credentialJwt, false, false, null, enforceExpClaim);
        } catch (InvalidJwtException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public static record PresentationConfirmation(String redirect_uri) {
    };
}
