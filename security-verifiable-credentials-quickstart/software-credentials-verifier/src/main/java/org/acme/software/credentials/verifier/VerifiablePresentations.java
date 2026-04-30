package org.acme.software.credentials.verifier;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VerifiablePresentations {

    private final List<VerifiedPresentation> presentations = new ArrayList<>();

    public void add(VerifiedPresentation presentation) {
        presentations.add(presentation);
    }

    public List<VerifiedPresentation> getAll() {
        return Collections.unmodifiableList(presentations);
    }
}
