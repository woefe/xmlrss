/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2016 Wolfgang Popp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
 * The Accumulator class provides applications the functionality of a cryptographic accumulator. Accumulators allow to
 * test for membership of a given value in a set, without revealing the individual members of the set.
 * <p>
 * An Accumulator object can be used to create witnesses for a given value or to verify the membership of a given value
 * in the accumulated set. Witnesses certify the membership of a given value in the accumulator.
 * <p>
 * An Accumulator object is used in two phases:
 * <ol>
 * <li> Initialization via: {@link #initWitness(KeyPair, byte[]...) initWitness},
 * {@link #initVerify(PublicKey, byte[]) initVerify}, {@link #restore(KeyPair, byte[]) restore}
 * <li> Creating witnesses or verifying membership. See {@link #verify(byte[], byte[]) verify},
 * {@link #createWitness(byte[]) createWitness}
 * </ol>
 *
 * @author Wolfgang Popp
 */
public abstract class Accumulator extends AccumulatorSpi {
    private Provider provider;
    private String algorithm;
    private STATE state;

    private enum STATE {
        UNINITIALIZED, CREATE_WITNESS, VERIFY
    }

    /**
     * Constructs a accumulator with the specified algorithm name.
     *
     * @param algorithm the algorithm of this accumulator
     */
    protected Accumulator(String algorithm) {
        this.algorithm = algorithm;
        this.state = STATE.UNINITIALIZED;
    }

    /**
     * Returns a Accumulator object that implements the specified accumulator algorithm.
     * <p>
     * This method traverses the list of registered security Providers, starting with the most preferred Provider. A new
     * Accumulator object encapsulating the AccumulatorSpi implementation from the first Provider that supports the
     * specified algorithm is returned.
     * <p>
     * Note that the list of registered providers may be retrieved via the <code>Security.getProviders()</code> method.
     *
     * @param algorithm the name of the requested algorithm
     * @return a new Accumulator object.
     * @throws NoSuchAlgorithmException if no Provider supports a Accumulator implementation for the specified
     *                                  algorithm.
     */
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

    /**
     * Returns a Accumulator object that implements the specified accumulator algorithm.
     * <p>
     * A new Accumulator object encapsulating the AccumulatorSpi implementation from the specified provider is returned.
     * The specified provider must be registered in the security provider list.
     * <p>
     * Note that the list of registered providers may be retrieved via the <code>Security.getProviders()</code> method.
     *
     * @param algorithm the name of the requested algorithm
     * @param provider  the name of the provider
     * @return a new Accumulator object.
     * @throws NoSuchProviderException  if the specified provider is not registered in the security provider list.
     * @throws NoSuchAlgorithmException if a AccumulatorSpi implementation for the specified algorithm is not available
     *                                  from the specified provider.
     */
    public static Accumulator getInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance("Accumulator",
                AccumulatorSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    /**
     * Returns a Accumulator object that implements the specified accumulator algorithm.
     * <p>
     * A new Accumulator object encapsulating the AccumulatorSpi implementation from the specified provider object is
     * returned. Note that the specified provider object does not have to be registered in the security provider list.
     *
     * @param algorithm the name of the requested algorithm
     * @param provider  the provider
     * @return a new Accumulator object.
     * @throws NoSuchAlgorithmException if a AccumulatorSpi implementation for the specified algorithm is not available
     *                                  from the specified provider.
     */
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

    /**
     * Returns the {@link Provider} of this Accumulator object
     *
     * @return the provider of this Accumulator object
     */
    public final Provider getProvider() {
        return this.provider;
    }

    /**
     * Initializes this object for creating witnesses. The given elements are accumulated into a short accumulator
     * value, which can be retrieved via {@link #getAccumulatorValue()}.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that Accumulator.
     *
     * @param keyPair  the keypair used for creating witnesses
     * @param elements all elements that are accumulated
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    public final void initWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException {
        state = STATE.CREATE_WITNESS;
        engineInitWitness(keyPair, elements);
    }

    /**
     * Initializes this object from the given accumulator value for creating witnesses. This method initializes the
     * Accumulator object from an already existing accumulator value, while
     * {@link #initWitness(KeyPair, byte[]...) initWitness} generates a new accumulator value.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that Accumulator.
     *
     * @param keyPair          the keypair used for creating witnesses
     * @param accumulatorValue the accumulator value as retrieved by {@link #getAccumulatorValue()}
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    public final void restore(KeyPair keyPair, byte[] accumulatorValue) throws InvalidKeyException {
        state = STATE.CREATE_WITNESS;
        engineRestore(keyPair, accumulatorValue);
    }

    /**
     * Initializes this Accumulator object for verification (membership testing).
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that Accumulator.
     *
     * @param publicKey        the public key of the identity who accumulated accumulated elements into the given
     *                         accumulator value
     * @param accumulatorValue the accumulator value as retrieved by {@link #getAccumulatorValue()}
     * @throws InvalidKeyException if the given key is inappropriate for initializing this Accumulator object.
     */
    public final void initVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException {
        state = STATE.VERIFY;
        engineInitVerify(publicKey, accumulatorValue);
    }

    /**
     * Creates a witness for the given element with regard to this accumulator object.
     *
     * @param element the element
     * @return the witness bytes certifying the membership of the element in the accumulator
     * @throws AccumulatorException if this Accumulator object is not initialized properly or if this accumulator
     *                              algorithm is unable to process the given element
     */
    public final byte[] createWitness(byte[] element) throws AccumulatorException {
        if (state == STATE.CREATE_WITNESS) {
            return engineCreateWitness(element);
        }
        throw new AccumulatorException("not initialized for creating witnesses");
    }

    /**
     * Verifies if the given witness certifies the membership of the given element in the accumulated set.
     *
     * @param witness the witness for the given element
     * @param element the element whose set-membersip is verfied
     * @return true if the given <code>witness</code> is indeed a witness for <code>element</code> being an element of
     * the accumulated set.
     * @throws AccumulatorException if this Accumulator object is not initialized properly or if this accumulator
     *                              algorithm is unable to process the given element
     */
    public final boolean verify(byte[] witness, byte[] element) throws AccumulatorException {
        if (state == STATE.VERIFY) {
            return engineVerify(witness, element);
        }
        throw new AccumulatorException("not initialized for verification");
    }

    /**
     * Returns the accumulator value of the accumulated elements
     *
     * @return the accumulator value
     * @throws AccumulatorException if this Accumulator object is not initialized properly or if this accumulator
     *                              algorithm is unable to process the given element
     */
    public final byte[] getAccumulatorValue() throws AccumulatorException {
        if (state != STATE.UNINITIALIZED) {
            return engineGetAccumulatorValue();
        }
        throw new AccumulatorException("not initialized");
    }

    /**
     * Returns the name of the algorithm for this accumulator object.
     *
     * @return the name of the algorithm for this accumulator object
     */
    public final String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * Returns the parameters used with this Accumulator object.
     * <p>
     * The returned parameters may be the same that were used to initialize this accumulator, or may contain a
     * combination of default and random parameter values used by the underlying accumulator implementation if this
     * accumulator requires algorithm parameters but was not initialized with any.
     *
     * @return the parameters used with this accumulator or null if no parameters are used
     */
    public final AlgorithmParameters getParameters() {
        return engineGetParameters();
    }

    /**
     * Initializes this accumulator with the specified parameter set.
     *
     * @param parameters the parameters
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this algorithm
     */
    public final void setParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        engineSetParameters(parameters);
    }


    /**
     * Returns a string representation of this accumulator object. The returned string includes information about the
     * initialization state of the object and the name of the algorithm used.
     *
     * @return a string representation of this Accumulator object
     */
    @Override
    public String toString() {
        return "Accumulator (Algorithm: " + getAlgorithm() + ", Initialization state: " + state + ")";
    }

    static class Delegate extends Accumulator {

        private AccumulatorSpi rssSPI;

        Delegate(AccumulatorSpi spi, String algorithm) {
            super(algorithm);
            this.rssSPI = spi;
        }

        @Override
        protected void engineInitWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException {
            rssSPI.engineInitWitness(keyPair, elements);
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
