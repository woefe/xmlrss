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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * This class defines the Service Provider Interface for the {@link Accumulator} class.
 * <p>
 * All abstract methods in this class must be implemented by cryptographic services providers who wish to supply the
 * implementation of a particular accumulator algorithm.
 *
 * @author Wolfgang Popp
 */
public abstract class AccumulatorSpi {

    /**
     * Initializes this accumulator engine for creating witnesses for the given elements under the given keypair.
     *
     * @param keyPair  the keypair used for creating witnesses
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    protected void engineInitWitness(KeyPair keyPair) throws InvalidKeyException {
        engineInitWitness(keyPair, new SecureRandom());
    }

    /**
     * Initializes this accumulator engine for creating witnesses for the given elements under the given keypair using
     * the given source of randomness.
     *
     * @param keyPair the keypair used for creating witnesses
     * @param random  the source of randomness
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    protected abstract void engineInitWitness(KeyPair keyPair, SecureRandom random) throws InvalidKeyException;

    /**
     * Digests the given elements to the accumulator value.
     * <p>
     * The accumulator value should be saved internally, because it is later used to create witnesses.
     *
     * @param elements the accumulated elements
     * @throws AccumulatorException if the given elements cannot be digested; e.g. the elements contain duplicates
     */
    protected abstract void engineDigest(byte[]... elements) throws AccumulatorException;

    /**
     * Restores the state of this accumulator engine for creating witnesses.
     * <p>
     * This accumulator is initialized with an already existing accumulator value. The state of this accumuator after a
     * call of this method should be the same as after a call of {@link #engineRestoreWitness(AccumulatorState)}.
     *
     * @param accumulatorValue the accumulator value as retrieved by {@link #engineGetAccumulatorValue()}
     * @param auxiliaryValue   the auxiliary value used by this accumulator as retrieved by {@link #engineGetAccumulatorValue()}
     * @param elements         the elements that were used to create the accumulator value
     * @throws AccumulatorException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    protected abstract void engineRestoreWitness(byte[] accumulatorValue, byte[] auxiliaryValue, byte[]... elements)
            throws AccumulatorException;

    /**
     * Restores the state of this accumulator engine for creating witnesses.
     * <p>
     * This accumulator is initialized with an already existing accumulator value. The state of this accumuator after a
     * call of this method should be the same as after a call of
     * {@link #engineRestoreWitness(byte[], byte[], byte[]...)}.
     * <p>
     * This method can be overridden in case additional helper values are added to a custom
     * <code>AccumulatorState</code>.
     *
     * @param savedState the saved state of an accumulator
     * @throws AccumulatorException if the given saved state cannot be used to restore this accumulator
     */
    protected void engineRestoreWitness(AccumulatorState savedState) throws AccumulatorException {
        engineRestoreWitness(savedState.accumulatorValue, savedState.auxiliaryValue, savedState.elements);
    }

    /**
     * Initializes this accumulator for verification (membership testing).
     *
     * @param publicKey the public key of the keypair that was used for creating witnesses.
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    protected abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    /**
     * Restores the accumulator state from the given accumulator value for verification.
     *
     * @param accumulatorValue the accumulator value
     */
    protected abstract void engineRestoreVerify(byte[] accumulatorValue);

    /**
     * Creates a witness for the given element.
     *
     * @param element the element
     * @return the witness certifying the membership of the element in the accumulated set
     * @throws AccumulatorException if this accumulator algorithm is unable to process the given element
     */
    protected abstract byte[] engineCreateWitness(byte[] element) throws AccumulatorException;

    /**
     * Checks whether the given witness certifies the membership of the given element in the accumulated set.
     *
     * @param witness the witness for the given element
     * @param element the element whose set-membersip is verfied
     * @return true if the given <code>witness</code> is indeed a witness for <code>element</code> being an element of
     * the accumulated set.
     * @throws AccumulatorException if this accumulator algorithm is unable to process the given element
     */
    protected abstract boolean engineVerify(byte[] witness, byte[] element) throws AccumulatorException;

    /**
     * Returns the accumulator value of the accumulated elements.
     *
     * @return the accumulator value
     * @throws AccumulatorException if the engine is not initialized properly
     */
    protected abstract byte[] engineGetAccumulatorValue() throws AccumulatorException;

    /**
     * Returns the auxiliary value used by this accumulator.
     *
     * @return the auxiliary value or null if this accumulator does not use an auxiliary value
     * @throws AccumulatorException if the auxiliary value cannot be retrieved
     */
    protected abstract byte[] engineGetAuxiliaryValue() throws AccumulatorException;

    /**
     * Returns the accumulator state that can be used to restore an accumulator.
     *
     * @return the accumulator state
     * @throws AccumulatorException if the accumulator state cannot be retrieved
     */
    protected abstract AccumulatorState engineGetAccumulatorState() throws AccumulatorException;

    /**
     * Returns the algorithm parameters used by this accumulator engine or null if this accumulator engine does not use
     * any parameters.
     *
     * @return the algorithm parameters or null if this accumulator engine does not use any parameters.
     */
    protected abstract AlgorithmParameters engineGetParameters();

    /**
     * Initializes this accumulator with the specified parameter set.
     *
     * @param parameters the parameters
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this algorithm
     */
    protected abstract void engineSetParameters(AlgorithmParameters parameters)
            throws InvalidAlgorithmParameterException;
}
