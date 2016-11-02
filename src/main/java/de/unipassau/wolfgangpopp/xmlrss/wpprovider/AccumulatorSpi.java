package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * @author Wolfgang Popp
 */
public abstract class AccumulatorSpi {
    protected abstract byte[] engineInitWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException;

    protected abstract void engineRestore(KeyPair keyPair, byte[] accumulatorValue) throws InvalidKeyException;

    protected abstract void engineInitVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException;

    protected abstract byte[] engineCreateWitness(byte[] element) throws AccumulatorException;

    protected abstract boolean engineVerify(byte[] witness, byte[] element) throws AccumulatorException;

    protected abstract byte[] engineGetAccumulatorValue() throws AccumulatorException;

    protected abstract AlgorithmParameters engineGetParameters();

    protected abstract void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException;
}
