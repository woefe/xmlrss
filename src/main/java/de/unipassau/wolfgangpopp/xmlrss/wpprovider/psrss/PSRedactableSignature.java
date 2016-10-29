package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.ModificationInstruction;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableSignature extends RedactableSignatureSpi {



    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {

    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {

    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {

    }

    protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {

    }

    protected void engineInitMerge(PublicKey publicKey) throws InvalidKeyException {

    }

    protected void engineAddPart(byte[] part, boolean admissible) throws SignatureException {

    }

    protected SignatureOutput engineSign() throws SignatureException {
        return null;
    }

    protected boolean engineVerify(SignatureOutput signature) throws SignatureException {
        return false;
    }

    protected SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
        return null;
    }

    protected SignatureOutput engineMerge(SignatureOutput signature1, SignatureOutput signature2) throws SignatureException {
        return null;
    }

    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }

    protected AlgorithmParameters engineGetParameters() {
        return null;
    }
}
