package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

public abstract class RedactableSignatureSpi {

    protected abstract void engineInitSign(KeyPair keyPair) throws InvalidKeyException;

    protected abstract void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException;

    protected abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    protected abstract void engineInitRedact(PublicKey publicKey) throws InvalidKeyException;

    protected abstract void engineInitMerge(PublicKey publicKey) throws InvalidKeyException;

    protected void engineInitUpdate(KeyPair privateKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support updating");
    }

    protected abstract void engineAddPart(byte[] part, boolean admissible) throws SignatureException;

    //protected abstract void engineAddAllAdmissibleParts(byte[]... parts) throws SignatureException;
    //protected abstract void engineAddAllNonAdmissibleParts(byte[]... parts) throws SignatureException;
    //protected abstract void engineAddAllAdmissibleParts(Collection<byte[]> parts) throws SignatureException;
    //protected abstract void engineAddAllNonAdmissibleParts(Collection<byte[]> parts) throws SignatureException;

    protected abstract SignatureOutput engineSign() throws SignatureException;

    protected abstract boolean engineVerify(SignatureOutput signature) throws SignatureException;

    protected abstract SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException;

    protected abstract SignatureOutput engineMerge(SignatureOutput signature1, SignatureOutput signature2) throws SignatureException;

    protected SignatureOutput engineUpdate(SignatureOutput original) throws SignatureException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support updating");
    }

    protected abstract ModificationInstruction engineNewModificationInstruction();

    protected abstract void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException;

    protected abstract AlgorithmParameters engineGetParameters();

}
