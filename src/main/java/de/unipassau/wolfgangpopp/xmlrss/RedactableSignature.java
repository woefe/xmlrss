package de.unipassau.wolfgangpopp.xmlrss;

import sun.security.jca.GetInstance;

import java.security.*;

public abstract class RedactableSignature extends RedactableSignatureSPI {

    private Provider provider;
    private String algorithm;

    protected RedactableSignature(String algorithm) {
        this.algorithm = algorithm;
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

    // TODO: 10/26/16 Handle state!!

    public void initSign(PublicKey publicKey) throws InvalidKeyException {
        engineInitSign(publicKey);
    }

    public void addPart(byte[] part, boolean admissible) throws SignatureException {
        engineAddPart(part, admissible);
    }

    public SignatureOutput sign() throws SignatureException {
        return engineSign();
    }


    public void initVerify(PublicKey publicKey) throws InvalidKeyException {
        engineInitVerify(publicKey);
    }

    public boolean verify(SignatureOutput signature) throws SignatureException {
        return engineVerify(signature);
    }


    public void initRedact(PublicKey publicKey /*TODO*/) throws InvalidKeyException {
        engineInitRedact(publicKey);
    }

    public SignatureOutput redact(SignatureOutput signature) throws SignatureException {
        return engineRedact(signature);
    }

    static class Delegate extends RedactableSignature {

        private RedactableSignatureSPI rssSPI;

        Delegate(RedactableSignatureSPI spi, String algorithm) {
            super(algorithm);
            this.rssSPI = spi;
        }

        @Override
        protected void engineInitSign(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitSign(publicKey);
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
        protected SignatureOutput engineRedact(SignatureOutput signature) throws SignatureException {
            return rssSPI.engineRedact(signature);
        }
    }


}
