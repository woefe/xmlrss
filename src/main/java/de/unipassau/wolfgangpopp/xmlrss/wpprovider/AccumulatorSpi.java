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
 * @author Wolfgang Popp
 */
public abstract class AccumulatorSpi {
    protected abstract void engineInitWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException;

    protected abstract void engineRestore(KeyPair keyPair, byte[] accumulatorValue) throws InvalidKeyException;

    protected abstract void engineInitVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException;

    protected abstract byte[] engineCreateWitness(byte[] element) throws AccumulatorException;

    protected abstract boolean engineVerify(byte[] witness, byte[] element) throws AccumulatorException;

    protected abstract byte[] engineGetAccumulatorValue() throws AccumulatorException;

    protected abstract AlgorithmParameters engineGetParameters();

    protected abstract void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException;
}
