package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorSpi;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * @author Wolfgang Popp
 */
public class PSAccumulator extends AccumulatorSpi{
    @Override
    protected byte[] engineInitWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException {
        return new byte[0];
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException {

    }

    @Override
    protected byte[] engineCreateWitness(byte[] element) throws AccumulatorException {
        return new byte[0];
    }

    @Override
    protected boolean engineVerify(byte[] witness, byte[] element) throws AccumulatorException {
        return false;
    }

    @Override
    protected byte[] engineGetAccumulatorValue() throws AccumulatorException {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }
}
