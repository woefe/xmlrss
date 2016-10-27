package de.unipassau.wolfgangpopp.xmlrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.ModificationInstruction;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureSPI;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

/**
 * Created by popeye on 10/27/16.
 */
public class TestDummy extends RedactableSignatureSPI {
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        System.out.println("initSign");
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        appRandom = random;
        engineInitSign(privateKey);
    }

    protected void engineAddPart(byte[] part, boolean admissible) throws SignatureException {
        System.out.println("addpart");

    }

    protected SignatureOutput engineSign() throws SignatureException {
        System.out.println("Sign");
        return null;
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        System.out.println("initVerify");

    }

    protected boolean engineVerify(SignatureOutput signature) throws SignatureException {
        System.out.println("verify");
        return false;
    }

    protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        System.out.println("initRedact");

    }

    protected SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
        System.out.println("redact");
        return null;
    }

    protected void engineSetParameters(AlgorithmParameters parameters) {

    }

    protected AlgorithmParameters engineGetParameters() {
        return null;
    }
}
