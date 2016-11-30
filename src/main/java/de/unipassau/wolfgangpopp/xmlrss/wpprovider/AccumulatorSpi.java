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
     * @param elements all elements that are accumulated
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    protected abstract void engineInitWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException;

    /**
     * Initializes this accumulator engine for creating witnesses under the given keypair. This accumulator is
     * initialized with an already existing accumulator value.
     *
     * @param keyPair          the keypair used for creating witnesses
     * @param accumulatorValue the accumulator value as retrieved by {@link #engineGetAccumulatorValue()}
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    protected abstract void engineRestore(KeyPair keyPair, byte[] accumulatorValue) throws InvalidKeyException;

    /**
     * Initializes this accumulator for verification (membership testing).
     *
     * @param publicKey        the public key of the keypair that was used for creating witnesses.
     * @param accumulatorValue the accumulator value as retrieved by {@link #engineGetAccumulatorValue()}
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this Accumulator object.
     */
    protected abstract void engineInitVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException;

    /**
     * Creates a witness for the given element.
     *
     * @param element the element
     * @return the witness certifying the membership of the element in the accumulated set
     * @throws AccumulatorException if the engine is not initialized properly or if this accumulator algorithm is unable
     *                              to process the given element
     */
    protected abstract byte[] engineCreateWitness(byte[] element) throws AccumulatorException;

    /**
     * Checks if the given witness certifies the membership of the given element in the accumulated set.
     *
     * @param witness the witness for the given element
     * @param element the element whose set-membersip is verfied
     * @return true if the given <code>witness</code> is indeed a witness for <code>element</code> being an element of
     * the accumulated set.
     * @throws AccumulatorException if the engine is not initialized properly or if this accumulator algorithm is unable
     *                              to process the given element
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
