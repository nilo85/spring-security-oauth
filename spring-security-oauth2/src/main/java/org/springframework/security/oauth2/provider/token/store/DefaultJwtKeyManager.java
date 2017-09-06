package org.springframework.security.oauth2.provider.token.store;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.crypto.sign.*;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

public class DefaultJwtKeyManager implements JwtKeyManager {

    private static final Log logger = LogFactory.getLog(DefaultJwtKeyManager.class);

    private String verifierKey = new RandomValueStringGenerator().generate();
    private String signingKey = verifierKey;
    private SignatureVerifier verifier;
    private Signer signer = new MacSigner(verifierKey);

    @Override
    public Signer getSigner() {
        return signer;
    }

    @Override
    public Map<String, String> getKey() {
        Map<String, String> result = new LinkedHashMap<String, String>();
        result.put("alg", signer.algorithm());
        result.put("value", verifierKey);
        return result;
    }

    @Override
    public boolean isPublic() {
        return signer instanceof RsaSigner;
    }

    public void setVerifier(SignatureVerifier verifier) {
        this.verifier = verifier;
    }

    public void setSigner(Signer signer) {
        this.signer = signer;
    }

    public void setKeyPair(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        Assert.state(privateKey instanceof RSAPrivateKey, "KeyPair must be an RSA ");
        signer = new RsaSigner((RSAPrivateKey) privateKey);
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        verifier = new RsaVerifier(publicKey);
        verifierKey = "-----BEGIN PUBLIC KEY-----\n" + new String(Base64.encode(publicKey.getEncoded()))
                + "\n-----END PUBLIC KEY-----";

    }

    public void setSigningKey(String key) {
        Assert.hasText(key);
        key = key.trim();

        this.signingKey = key;

        if (isPublic(key)) {
            signer = new RsaSigner(key);
            logger.info("Configured with RSA signing key");
        }
        else {
            // Assume it's a MAC key
            this.verifierKey = key;
            signer = new MacSigner(key);
        }
    }

    /**
     * @return true if the key has a public verifier
     */
    private boolean isPublic(String key) {
        return key.startsWith("-----BEGIN");
    }

    public void setVerifierKey(String verifierKey) {
        this.verifierKey = verifierKey;
    }

    @Override
    public SignatureVerifier getVerifier() {
        return verifier;
    }

    public void afterPropertiesSet() {
        if (verifier != null) {
            // Assume signer also set independently if needed
            return;
        }
        SignatureVerifier verifier = new MacSigner(verifierKey);
        try {
            verifier = new RsaVerifier(verifierKey);
        }
        catch (Exception e) {
            logger.warn("Unable to create an RSA verifier from verifierKey (ignoreable if using MAC)");
        }
        // Check the signing and verification keys match
        if (signer instanceof RsaSigner) {
            byte[] test = "test".getBytes();
            try {
                verifier.verify(test, signer.sign(test));
                logger.info("Signing and verification RSA keys match");
            }
            catch (InvalidSignatureException e) {
                logger.error("Signing and verification RSA keys do not match");
            }
        }
        else if (verifier instanceof MacSigner) {
            // Avoid a race condition where setters are called in the wrong order. Use of
            // == is intentional.
            Assert.state(this.signingKey == this.verifierKey,
                    "For MAC signing you do not need to specify the verifier key separately, and if you do it must match the signing key");
        }
        this.verifier = verifier;
    }
}
