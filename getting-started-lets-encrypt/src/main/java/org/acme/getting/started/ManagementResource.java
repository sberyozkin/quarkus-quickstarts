package org.acme.getting.started;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.Optional;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.wildfly.security.x500.cert.acme.AcmeException;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/acme")
public class ManagementResource {
    
    @ConfigProperty(name = "email")
    String contactEmail;

    @ConfigProperty(name = "domain")
    String domain;

    @ConfigProperty(name = "staging", defaultValue = "true")
    boolean staging;

    @ConfigProperty(name = "lets-encrypt-path", defaultValue = ".lets-encrypt")
    String letsEncryptPath;
    @ConfigProperty(name = "pem-folder-path")
    Optional<String> pemFolderPath;
    @ConfigProperty(name = "certificate-pem-file", defaultValue = "cert.pem")
    String certPemFile;
    @ConfigProperty(name = "key-pem-file", defaultValue = "key.pem")
    String keyPemFile;

    private final AcmeClient acmeClient;
    
    public ManagementResource(@ConfigProperty(name = "management-url") String managementUrl,
                              @ConfigProperty(name = "management-user") Optional<String> managementUser,
                              @ConfigProperty(name = "management-password") Optional<String> managementPassword,
                              @ConfigProperty(name = "management-key") Optional<String> managementKey) {
        this.acmeClient = new AcmeClient(managementUrl, managementUser, managementPassword, managementKey);
    }

    @GET
    @Path("/prepare")
    public void prepare() {
        AcmeActions.prepare(letsEncryptPath);
    }
    
    @GET
    @Path("/create-account")
    public String createAccount() {
        return AcmeActions.createAccount(acmeClient, letsEncryptPath, staging, contactEmail);
    }
    
    @GET
    @Path("/first-certificate")
    @Produces(MediaType.APPLICATION_JSON)
    public String firstCertificate() {
        return AcmeActions.firstCertificate(acmeClient, letsEncryptPath, staging, domain, 
                pemFolderPath.get() + "/" + certPemFile, 
                pemFolderPath.get() + "/" + keyPemFile);
    }

    @GET
    @Path("/renew-certificate")
    @Produces(MediaType.APPLICATION_JSON)
    public String renewCertificate() throws AcmeException, CertificateEncodingException {
        return AcmeActions.renewCertificate(acmeClient, letsEncryptPath, staging, domain, 
                pemFolderPath.get() + "/" + certPemFile, 
                pemFolderPath.get() + "/" + keyPemFile);
    }
    
    @GET
    @Path("/deactivate-account")
    public void deactivateAccount() throws IOException {
        AcmeActions.deactivateAccount(acmeClient, letsEncryptPath, staging);
    }

}