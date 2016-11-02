package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import sun.security.jca.GetInstance;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public abstract class Accumulator extends AccumulatorSpi {
    private Provider provider;
    private String algorithm;
    private STATE state;

    private enum STATE {
        UNINITIALIZED, CREATE_WITNESS, VERIFY
    }

    protected Accumulator(String algorithm) {
        this.algorithm = algorithm;
        this.state = STATE.UNINITIALIZED;
    }

    public static Accumulator getInstance(String algorithm) throws NoSuchAlgorithmException {
        NoSuchAlgorithmException failure = new NoSuchAlgorithmException(algorithm + "Accumulator not available");
        List<Provider.Service> services = GetInstance.getServices("Accumulator", algorithm);

        for (Provider.Service service : services) {
            try {
                GetInstance.Instance instance = GetInstance.getInstance(service, AccumulatorSpi.class);
                return getInstance(instance, algorithm);
            } catch (NoSuchAlgorithmException e) {
                failure = e;
            }
        }
        throw failure;
    }

    public static Accumulator getInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance("Accumulator",
                AccumulatorSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    public static Accumulator getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        GetInstance.Instance instance = GetInstance.getInstance("Accumulator",
                AccumulatorSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    private static Accumulator getInstance(GetInstance.Instance instance, String algorithm) {
        Accumulator acc;
        if (instance.impl instanceof Accumulator) {
            acc = (Accumulator) instance.impl;
            acc.algorithm = algorithm;
        } else {
            AccumulatorSpi spi = (AccumulatorSpi) instance.impl;
            acc = new Delegate(spi, algorithm);
        }
        acc.provider = instance.provider;
        return acc;
    }

    public final Provider getProvider() {
        return this.provider;
    }

    public final byte[] initWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException {
        state = STATE.CREATE_WITNESS;
        return engineInitWitness(keyPair, elements);
    }

    public final void restore(KeyPair keyPair, byte[] accumulatorValue) throws InvalidKeyException {
        state = STATE.CREATE_WITNESS;
        engineRestore(keyPair, accumulatorValue);
    }

    public final void initVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException {
        state = STATE.VERIFY;
        engineInitVerify(publicKey, accumulatorValue);
    }

    public final byte[] createWitness(byte[] element) throws AccumulatorException {
        if (state == STATE.CREATE_WITNESS) {
            return engineCreateWitness(element);
        }
        throw new AccumulatorException("not initialized for creating witnesses");
    }

    public final boolean verify(byte[] witness, byte[] element) throws AccumulatorException {
        if (state == STATE.VERIFY) {
            return engineVerify(witness, element);
        }
        throw new AccumulatorException("not initialized for verification");
    }

    public final byte[] getAccumulatorValue() throws AccumulatorException {
        if (state != STATE.UNINITIALIZED) {
            return engineGetAccumulatorValue();
        }
        throw new AccumulatorException("not initialized");
    }

    public final String getAlgorithm() {
        return this.algorithm;
    }

    public final AlgorithmParameters getParameters() {
        return engineGetParameters();
    }

    public final void setParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        engineSetParameters(parameters);
    }


    @Override
    public String toString() {
        return "RedactableSignature (Algorithm: " + getAlgorithm() + ", Initialization state: " + state + ")";
    }

    static class Delegate extends Accumulator {

        private AccumulatorSpi rssSPI;

        Delegate(AccumulatorSpi spi, String algorithm) {
            super(algorithm);
            this.rssSPI = spi;
        }

        @Override
        protected byte[] engineInitWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException {
            return rssSPI.engineInitWitness(keyPair, elements);
        }

        @Override
        protected void engineRestore(KeyPair keyPair, byte[] accumulatorValue) throws InvalidKeyException {
            rssSPI.engineRestore(keyPair, accumulatorValue);
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException {
            rssSPI.engineInitVerify(publicKey, accumulatorValue);
        }

        @Override
        protected byte[] engineCreateWitness(byte[] element) throws AccumulatorException {
            return rssSPI.engineCreateWitness(element);
        }

        @Override
        protected boolean engineVerify(byte[] witness, byte[] element) throws AccumulatorException {
            return rssSPI.engineVerify(witness, element);
        }

        @Override
        protected byte[] engineGetAccumulatorValue() throws AccumulatorException {
            return rssSPI.engineGetAccumulatorValue();
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            return rssSPI.engineGetParameters();
        }

        @Override
        protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
            rssSPI.engineSetParameters(parameters);
        }
    }
}
