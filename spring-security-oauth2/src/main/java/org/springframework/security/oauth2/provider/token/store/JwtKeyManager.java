package org.springframework.security.oauth2.provider.token.store;

import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;

import java.util.Map;

/**
 * TBD
 *
 * @author Niklas Loenn
 *
 */
public interface JwtKeyManager {
    Signer getSigner();

    Map<String,String> getKey();

    boolean isPublic();

    SignatureVerifier getVerifier();
}
