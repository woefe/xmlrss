package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import sun.security.jca.GetInstance;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;

public abstract class RedactableSignature extends RedactableSignatureSPI {

    private Provider provider;
    private String algorithm;
    private STATE state;

    private enum STATE {
        UNINITIALIZED, SIGN, REDACT, VERIFY
    }

    protected RedactableSignature(String algorithm) {
        this.algorithm = algorithm;
        this.state = STATE.UNINITIALIZED;
    }

    public static RedactableSignature getInstance(String algorithm, String provider) throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance("RedactableSignature", RedactableSignatureSPI.class, algorithm, provider);

        RedactableSignature sig;
        if (instance.impl instanceof RedactableSignature) {
            sig = (RedactableSignature) instance.impl;
            sig.algorithm = algorithm;
        } else {
            RedactableSignatureSPI spi = (RedactableSignatureSPI) instance.impl;
            sig = new Delegate(spi, algorithm);
        }
        sig.provider = instance.provider;
        return sig;

    }

    public void initSign(KeyPair keyPair) throws InvalidKeyException {
        state = STATE.SIGN;
        engineInitSign(keyPair);
    }

    public void addPart(byte[] part, boolean admissible) throws SignatureException {
        if (state != STATE.UNINITIALIZED) {
            engineAddPart(part, admissible);
        }
        throw new SignatureException("not initialized");
    }

    public SignatureOutput sign() throws SignatureException {
        if (state == STATE.SIGN) {
            return engineSign();
        }
        throw new SignatureException("not initialized for signing");
    }


    public void initVerify(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.VERIFY;
        engineInitVerify(publicKey);
    }

    public boolean verify(SignatureOutput signature) throws SignatureException {
        if (state == STATE.VERIFY) {
            return engineVerify(signature);
        }
        throw new SignatureException("not initialized for verification");
    }


    public void initRedact(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.REDACT;
        engineInitRedact(publicKey);
    }

    public SignatureOutput redact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
        if (state == STATE.REDACT) {
            return engineRedact(signature, mod);
        }
        throw new SignatureException("not initialized for redaction");
    }

    static class Delegate extends RedactableSignature {

        private RedactableSignatureSPI rssSPI;

        Delegate(RedactableSignatureSPI spi, String algorithm) {
            super(algorithm);
            this.rssSPI = spi;
        }

        @Override
        protected void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
            rssSPI.engineInitSign(keyPair);
        }

        @Override
        protected void engineAddPart(byte[] part, boolean admissible) throws SignatureException {
            rssSPI.engineAddPart(part, admissible);
        }

        @Override
        protected SignatureOutput engineSign() throws SignatureException {
            return rssSPI.engineSign();
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitVerify(publicKey);
        }

        @Override
        protected boolean engineVerify(SignatureOutput signature) throws SignatureException {
            return rssSPI.engineVerify(signature);
        }

        @Override
        protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitRedact(publicKey);
        }

        @Override
        protected SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
            return rssSPI.engineRedact(signature, mod);
        }
    }
}
