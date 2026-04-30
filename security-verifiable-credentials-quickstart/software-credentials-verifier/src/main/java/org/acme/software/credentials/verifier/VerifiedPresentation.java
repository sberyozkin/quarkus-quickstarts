package org.acme.software.credentials.verifier;

import com.authlete.sd.SDJWT;

public record VerifiedPresentation(SDJWT sdjwt, String sub, String vct) {
}
