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
import java.security.SecureRandom;
import java.util.List;

/**
 * The Accumulator class provides applications the functionality of a cryptographic accumulator. Accumulators allow to
 * test for membership of a given value in a set, without revealing the individual members of the set.
 * <p>
 * An Accumulator object can be used to create witnesses for a given value or to verify the membership of a given value
 * in the accumulated set. Witnesses certify the membership of a given value in the accumulator.
 * <p>
 *
 * Creating witnesses for newly generated accumulator value:
 * <ol>
 * <li> {@link #initWitness(KeyPair)}
 * <li> {@link #digest(byte[]...)}
 * <li> {@link #createWitness(byte[])}
 * </ol>
 *
 * Creating witnesses for existing accumulator value:
 * <ol>
 * <li> {@link #initWitness(KeyPair)}
 * <li> {@link #restoreWitness(AccumulatorState)}
 * <li> {@link #createWitness(byte[])}
 * </ol>
 *
 * Verifying (witnesses, element):
 * <ol>
 * <li> {@link #initVerify(PublicKey)}
 * <li> {@link #restoreVerify(byte[])}
 * <li> {@link #verify(byte[], byte[])}
 * </ol>
 *
 * @author Wolfgang Popp
 */
public abstract class Accumulator {
    private Provider provider;
    private String algorithm;
    private STATE state;
    private final AccumulatorSpi engine;

    private enum STATE {
        UNINITIALIZED, CREATE_WITNESS, VERIFY
    }

    /**
     * Constructs an accumulator with the specified algorithm name and engine.
     *
     * @param algorithm the algorithm of this accumulator
     * @param engine    the actual implementation
     */
    protected Accumulator(AccumulatorSpi engine, String algorithm) {
        this.algorithm = algorithm;
        this.engine = engine;
        this.state = STATE.UNINITIALIZED;
    }

    /**
     * Returns an Accumulator object that implements the specified accumulator algorithm.
     * <p>
     * This method traverses the list of registered security Providers, starting with the most preferred Provider. A new
     * Accumulator object encapsulating the AccumulatorSpi implementation from the first Provider that supports the
     * specified algorithm is returned.
     * <p>
     * Note that the list of registered providers may be retrieved via the <code>Security.getProviders()</code> method.
     *
     * @param algorithm the name of the requested algorithm
     * @return a new Accumulator object
     * @throws NoSuchAlgorithmException if no Provider supports an Accumulator implementation for the specified
     *                                  algorithm
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
     * Returns an Accumulator object that implements the specified accumulator algorithm.
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
     * @throws NoSuchAlgorithmException if an AccumulatorSpi implementation for the specified algorithm is not available
     *                                  from the specified provider.
     */
    public static Accumulator getInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance("Accumulator",
                AccumulatorSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    /**
     * Returns an Accumulator object that implements the specified accumulator algorithm.
     * <p>
     * A new Accumulator object encapsulating the AccumulatorSpi implementation from the specified provider object is
     * returned. Note that the specified provider object does not have to be registered in the security provider list.
     *
     * @param algorithm the name of the requested algorithm
     * @param provider  the provider
     * @return a new Accumulator object.
     * @throws NoSuchAlgorithmException if an AccumulatorSpi implementation for the specified algorithm is not available
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
     * Initializes this object for creating witnesses.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that Accumulator.
     *
     * @param keyPair  the keypair used for creating witnesses
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    public final void initWitness(KeyPair keyPair) throws InvalidKeyException {
        state = STATE.CREATE_WITNESS;
        engine.engineInitWitness(keyPair);
    }

    /**
     * Initializes this object for creating witnesses.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that Accumulator.
     *
     * @param keyPair the keypair used for creating witnesses
     * @param random  the source of randomness for this accumulator
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    public final void initWitness(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        state = STATE.CREATE_WITNESS;
        engine.engineInitWitness(keyPair, random);
    }

    /**
     * Digests the given elements into a short accumulator value that is then used for creation of witnesses. The
     * accumulator can retrieved via {@link #getAccumulatorValue()}. In some implementations the given elements may not
     * contain duplicates.
     *
     * @param elements the elements that are digested to an accumulator value
     * @throws AccumulatorException if this Accumulator is not initialized properly or if the accumulator value cannot
     *                              be created from the given elements
     */
    public final void digest(byte[]... elements) throws AccumulatorException {
        if (state != STATE.CREATE_WITNESS) {
            throw new AccumulatorException("not initialized for creating witnesses");
        }
        engine.engineDigest(elements);
    }

    /**
     * Restores this accumulator from the given accumulator state for creating witnesses. This method initializes the
     * Accumulator object from an already existing accumulator value, while {@link #digest(byte[]...)} generates a new
     * accumulator value.
     *
     * @param savedState a saved accumulator state as retrieved by {@link #getAccumulatorState()}
     * @throws AccumulatorException if this Accumulator is not initialized properly or if the given saved state cannot
     *                              be used to restore this accumulator
     */
    public final void restoreWitness(AccumulatorState savedState) throws AccumulatorException {
        if (state != STATE.CREATE_WITNESS) {
            throw new AccumulatorException("not initialized for creating witnesses");
        }
        engine.engineRestoreWitness(savedState);
    }

    /**
     * Restores this accumulator from the given accumulator and auxiliary values.
     * <p>
     * This method is similar to  {@link #restoreWitness(AccumulatorState)}, but an AccumulatorState object might
     * contain additional data which may lead to better performance. The {@link #restoreWitness(AccumulatorState)}
     * should therefore be preferred over this method.
     *
     * @param accumulatorValue the accumulator value as retrieved by {@link #getAccumulatorValue()}
     * @param auxiliaryValue   the auxiliary value as retrieved by {@link #getAuxiliaryValue()}
     * @param elements         the elements that were used to create the accumulator value
     * @throws AccumulatorException if this Accumulator is not initialized properly or if this accumulator cannot be
     *                              restored from the given values and elements
     */
    public final void restoreWitness(byte[] accumulatorValue, byte[] auxiliaryValue, byte[]... elements) throws AccumulatorException {
        if (state != STATE.CREATE_WITNESS) {
            throw new AccumulatorException("not initialized for creating witnesses");
        }
        engine.engineRestoreWitness(accumulatorValue, auxiliaryValue, elements);
    }

    /**
     * Initializes this Accumulator object for verification (membership testing).
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that Accumulator.
     *
     * @param publicKey        the public key of the identity who accumulated accumulated elements into the given
     *                         accumulator value
     * @throws InvalidKeyException if the given key is inappropriate for initializing this Accumulator object.
     */
    public final void initVerify(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.VERIFY;
        engine.engineInitVerify(publicKey);
    }

    /**
     * Restores this accumulator for verification from the given accumulator value.
     *
     * @param accumulatorValue the accumulator value as retrieved by {@link #getAccumulatorValue()}
     * @throws AccumulatorException if this Accumulator is not initialized properly or if this accumulator cannot be
     *                              restored from the given value
     */
    public final void restoreVerify(byte[] accumulatorValue) throws AccumulatorException {
        if (state != STATE.VERIFY) {
            throw new AccumulatorException("not initialized for verification");
        }
        engine.engineRestoreVerify(accumulatorValue);
    }

    /**
     * Creates a witness for the given element with regard to the private key and accumulator value.
     *
     * @param element the element
     * @return the witness bytes certifying the membership of the element in the accumulator
     * @throws AccumulatorException if this Accumulator object is not initialized properly or if this accumulator
     *                              algorithm is unable to process the given element
     */
    public final byte[] createWitness(byte[] element) throws AccumulatorException {
        if (state == STATE.CREATE_WITNESS) {
            return engine.engineCreateWitness(element);
        }
        throw new AccumulatorException("not initialized for creating witnesses");
    }

    /**
     * Verifies whether the given witness certifies the membership of the given element in the accumulated set.
     *
     * @param witness the witness for the given element.
     * @param element the element whose set-membersip is verfied.
     * @return true if the given <code>witness</code> is indeed a witness for <code>element</code> being an element of
     * the accumulated set.
     * @throws AccumulatorException if this Accumulator object is not initialized properly or if this accumulator
     *                              algorithm is unable to process the given element.
     */
    public final boolean verify(byte[] witness, byte[] element) throws AccumulatorException {
        if (state == STATE.VERIFY) {
            return engine.engineVerify(witness, element);
        }
        throw new AccumulatorException("not initialized for verification");
    }

    /**
     * Returns the accumulator value of the accumulated elements.
     *
     * @return the accumulator value.
     * @throws AccumulatorException if this Accumulator object is not initialized properly or if this accumulator
     *                              algorithm is unable to process the given element.
     */
    public final byte[] getAccumulatorValue() throws AccumulatorException {
        if (state != STATE.UNINITIALIZED) {
            return engine.engineGetAccumulatorValue();
        }
        throw new AccumulatorException("not initialized");
    }

    /**
     * Returns the auxiliary value of this accumulator.
     * <p>
     * The auxiliary value is used by some implementations to make the accumulator indistinguishable. See
     * "Indistinguishability of One-Way Accumulators" by H. de Meer et al.
     *
     * @return the auxiliary value used by this accumulator or null.
     * @throws AccumulatorException if this Accumulator object is not initialized properly or the auxiliary value cannot
     *                              be retrieved.
     */
    public final byte[] getAuxiliaryValue() throws AccumulatorException {
        if (state == STATE.CREATE_WITNESS) {
            return engine.engineGetAuxiliaryValue();
        }
        throw new AccumulatorException("not initialized for creating witnesses");
    }

    /**
     * Returns the current state of this accumulator.
     * <p>
     * The AccumulatorState object contains the accumulator and auxiliary value and may additionally contain extra data
     * to speed up restoration.
     *
     * @return the current accumulator state
     * @throws AccumulatorException if this Accumulator object is not initialized properly or the state cannot be
     *                              retrieved
     */
    public final AccumulatorState getAccumulatorState() throws AccumulatorException {
        if (state == STATE.CREATE_WITNESS) {
            return engine.engineGetAccumulatorState();
        }
        throw new AccumulatorException("not initialized for creating witnesses");
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
        return engine.engineGetParameters();
    }

    /**
     * Initializes this accumulator with the specified parameter set.
     *
     * @param parameters the parameters
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this algorithm
     */
    public final void setParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        engine.engineSetParameters(parameters);
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
        Delegate(AccumulatorSpi engine, String algorithm) {
            super(engine, algorithm);
        }
    }
}
