package org.acme.getting.started;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.wildfly.security.x500.cert.X509CertificateChainAndSigningKey;
import org.wildfly.security.x500.cert.acme.AcmeAccount;
import org.wildfly.security.x500.cert.acme.AcmeException;

import io.quarkus.logging.Log;
import io.quarkus.tls.cli.helpers.LetsEncryptHelpers;
import io.vertx.core.json.JsonObject;
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
    Optional<String> letsEncryptPath;
    @ConfigProperty(name = "pem-folder-path")
    Optional<String> pemFolderPath;
    @ConfigProperty(name = "certificate-pem-file", defaultValue = "cert.pem")
    String certPemFile;
    @ConfigProperty(name = "key-pem-file", defaultValue = "key.pem")
    String keyPemFile;

    private final AcmeClient acmeClient;
    
    public ManagementResource(AcmeClient acmeClient) {
        this.acmeClient = acmeClient;
    }

    @GET
    @Path("/first-certificate")
    @Produces(MediaType.APPLICATION_JSON)
    public String firstCertificate() throws AcmeException, CertificateEncodingException {
        Log.infof("Requesting %s Let's Encrypt certificate chain and private key", (staging ? "staging" : ""));
        JsonObject chainAndKey = obtainCertificateChain();
        return chainAndKey.encode();
    }

    @GET
    @Path("/renew-certificate")
    @Produces(MediaType.APPLICATION_JSON)
    public String renewCertificate() throws AcmeException, CertificateEncodingException {
        Log.infof("Requesting %s Let's Encrypt certificate chain and private key", (staging ? "staging" : ""));
        JsonObject chainAndKey = obtainCertificateChain();

        return chainAndKey.encode();
    }
    
    @GET
    @Path("/create-account")
    public String createAccount() throws AcmeException, CertificateEncodingException {
        Log.infof("Creating %s Let's Encrypt account for %s", (staging ? "staging" : ""), contactEmail);
        
        AcmeAccount acmeAccount = AcmeAccount.builder().setTermsOfServiceAgreed(true)
                .setServerUrl("https://acme-v02.api.letsencrypt.org/directory")
                .setStagingServerUrl("https://acme-staging-v02.api.letsencrypt.org/directory")
                .setContactUrls(new String[] { "mailto:" + contactEmail }).build();
        
        if (!acmeClient.createAccount(acmeAccount, staging)) {
            Log.infof("%s Let's Encrypt account %s for %s already exists", (staging ? "Staging" : ""), acmeAccount.getAccountUrl(), contactEmail);
        } else {
            Log.infof("%s Let's Encrypt account %s for %s has been created", (staging ? "Staging" : ""), acmeAccount.getAccountUrl(), contactEmail);
        }
        JsonObject accountJson = convertAccountToJson(acmeAccount);
        saveAccount(accountJson);
        return accountJson.encode();
    }
    
    
    @GET
    @Path("/deactivate-account")
    public void deactivateAccount() throws IOException {
        AcmeAccount acmeAccount = getAccount();
        Log.infof("Deactivating %s Let's Encrypt account for %s", (staging ? "staging" : ""), contactEmail);
        acmeClient.deactivateAccount(acmeAccount, staging);
        
        Log.infof("Removing account file from %s", letsEncryptPath.get());
        
        java.nio.file.Path accountPath = Paths.get(letsEncryptPath.get() + "/account.json");
        Files.deleteIfExists(accountPath);
    }
    
    private JsonObject obtainCertificateChain() throws AcmeException, CertificateEncodingException {
        AcmeAccount acmeAccount = getAccount();
        
        X509CertificateChainAndSigningKey certChainAndPrivateKey;
        try {
            certChainAndPrivateKey = acmeClient.obtainCertificateChain(acmeAccount, staging, domain);
        } catch (AcmeException t) {
            throw new RuntimeException(t.getMessage());
        }
        Log.infof("Converting certificate chain and private key to PEM");
        
        java.nio.file.Path certPemPath = Paths.get(pemFolderPath.get() + "/" + certPemFile);
        java.nio.file.Path keyPemPath = Paths.get(pemFolderPath.get() + "/" + keyPemFile);
        try {
            LetsEncryptHelpers.writePrivateKeyAndCertificateChainsAsPem(certChainAndPrivateKey.getSigningKey(),
                certChainAndPrivateKey.getCertificateChain(), keyPemPath.toFile(), certPemPath.toFile());
        } catch (Exception ex) {
            throw new RuntimeException("Failure to copy certificate pem");
        }
        
        acmeClient.certificateChainAndKeyAreReady();

        return new JsonObject().put("account", convertAccountToJson(acmeAccount));
    }

    private JsonObject convertAccountToJson(AcmeAccount acmeAccount) throws CertificateEncodingException {
        JsonObject json = new JsonObject();
        json.put("account-url", acmeAccount.getAccountUrl());
        json.put("contact-url", acmeAccount.getContactUrls()[0]);
        if (acmeAccount.getPrivateKey() != null) { 
            json.put("private-key", new String(Base64.getEncoder().encode(acmeAccount.getPrivateKey().getEncoded()),
                    StandardCharsets.US_ASCII));
        }
        if (acmeAccount.getCertificate() != null) {
            json.put("certificate", new String(Base64.getEncoder().encode(acmeAccount.getCertificate().getEncoded()),
                    StandardCharsets.US_ASCII));
        }
        if (acmeAccount.getKeyAlgorithmName() != null) {
            json.put("key-algorithm", acmeAccount.getKeyAlgorithmName());
        }
        json.put("key-size", acmeAccount.getKeySize());
        return json;
    }
    
    private AcmeAccount getAccount() {
        Log.infof("Getting account from %s", letsEncryptPath.get());
        
        JsonObject json = readAccountJson();
        AcmeAccount.Builder builder = AcmeAccount.builder().setTermsOfServiceAgreed(true)
                .setServerUrl("https://acme-v02.api.letsencrypt.org/directory")
                .setStagingServerUrl("https://acme-staging-v02.api.letsencrypt.org/directory");
        
        String keyAlgorithm = json.getString("key-algorithm");
        builder.setKeyAlgorithmName(keyAlgorithm);
        builder.setKeySize(json.getInteger("key-size"));
        
        if (json.containsKey("private-key") && json.containsKey("certificate")) {
            PrivateKey privateKey = getPrivateKey(json.getString("private-key"), keyAlgorithm);
            X509Certificate certificate = getCertificate(json.getString("certificate"));
            
            builder.setKey(certificate, privateKey);
        }
        
        AcmeAccount acmeAccount = builder.build();
        
        acmeAccount.setContactUrls(new String[] {json.getString("contact-url")});
        acmeAccount.setAccountUrl(json.getString("account-url"));
        
        return acmeAccount;
    }
        
    private X509Certificate getCertificate(String encodedCert) {
        try {
            byte[] encodedBytes = Base64.getDecoder().decode(encodedCert);
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(encodedBytes));
        } catch (Exception ex) {
            throw new RuntimeException("Failure to create a certificate", ex);
        }
    }

    private PrivateKey getPrivateKey(String encodedKey, String keyAlgorithm) {
        try {
            KeyFactory f = KeyFactory.getInstance((keyAlgorithm == null || "RSA".equals(keyAlgorithm) ? "RSA" : "EC"));
            byte[] encodedBytes = Base64.getDecoder().decode(encodedKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedBytes);
            return f.generatePrivate(spec);
        } catch (Exception ex) {
            throw new RuntimeException("Failure to create a private key", ex);
        }
    }

    private JsonObject readAccountJson() {
        java.nio.file.Path accountPath = Paths.get(letsEncryptPath.get() + "/account.json");
        try (FileInputStream fis = new FileInputStream(accountPath.toString())) {
            return new JsonObject(new String(fis.readAllBytes(), StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new RuntimeException("Unable to read the account file, you must create account first");
        }
    }
        
    private void saveAccount(JsonObject accountJson) {
        Log.infof("Saving account to %s", letsEncryptPath.get());
        
        // If more than one account must be supported, we can save accounts to unique files in .lets-encrypt/accounts
        // and require an account alias/id during operations requiring an account
        java.nio.file.Path accountPath = Paths.get(letsEncryptPath.get() + "/account.json");
        try {
            Files.copy(new ByteArrayInputStream(accountJson.encode().getBytes(StandardCharsets.US_ASCII)), accountPath,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ex) {
            throw new RuntimeException("Failure to save the account", ex);
        }
    }
}