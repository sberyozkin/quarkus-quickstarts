package org.acme.software.credentials.wallet;

import java.io.Serializable;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Cacheable;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;

@Entity
@Cacheable
public class VerifiableCredentialEntity extends PanacheEntityBase {

    @EmbeddedId
    public CredentialId id;

    @Column(length = 4096)
    public String vc;

    // This one can be stored in the encrypted form
    @Column(length = 4096, nullable = false)
    public String privateKey;

    public VerifiableCredentialEntity() {
    }

    public VerifiableCredentialEntity(String name, String credentialId, String vc, String privateKey) {
        this.id = new CredentialId(name, credentialId);
        this.vc = vc;
        this.privateKey = privateKey;
    }

    @Embeddable
    public record CredentialId(@Column(name = "name", nullable = false) String name,
            @Column(name = "credentialId", nullable = false) String credentialId) implements Serializable {
    }
}