package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

/**
 * Created by popeye on 10/27/16.
 */
public abstract class ModificationInstruction {

    public static ModificationInstruction forAlgorithm(RedactableSignature algorithm) {
        return algorithm.newModificationInstruction();
    }

    public static ModificationInstruction forAlgorithm(String algorithm) throws NoSuchAlgorithmException {
        return RedactableSignature.getInstance(algorithm).newModificationInstruction();
    }

    public static ModificationInstruction forAlgorithm(String algorithm, String provider) throws NoSuchProviderException, NoSuchAlgorithmException {
        return RedactableSignature.getInstance(algorithm, provider).newModificationInstruction();
    }

    public static ModificationInstruction forAlgorithm(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        return RedactableSignature.getInstance(algorithm, provider).newModificationInstruction();
    }

    public abstract void add(byte[] part) throws IllegalModificationException;
}
