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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorState;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.CryptoUtils.fullDomainHash;

/**
 * @author Wolfgang Popp
 */
public class PSAccumulator extends AccumulatorSpi {

    private PSRSSPrivateKey privateKey;
    private PSRSSPublicKey publicKey;
    private byte[] accumulatorValueRaw;
    private BigInteger accumulatorValue;
    private SecureRandom random;

    @Override
    protected void engineInitWitness(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        setKeyPair(keyPair);
        this.random = random;
    }

    @Override
    protected void engineDigest(byte[]... elements) {
        BigInteger n = publicKey.getKey();

        int bitLength = n.bitLength();
        BigInteger digest;

        do {
            digest = new BigInteger(bitLength, random);
        } while (digest.compareTo(n) == 1 || !digest.gcd(n).equals(BigInteger.ONE));

        accumulatorValueRaw = digest.toByteArray();
        accumulatorValue = new BigInteger(accumulatorValueRaw);
    }

    @Override
    protected void engineRestoreWitness(byte[] accumulatorValue, byte[] auxiliaryValue, byte[]... elements)
            throws AccumulatorException {

        this.accumulatorValueRaw = Arrays.copyOf(accumulatorValue, accumulatorValue.length);
        this.accumulatorValue = new BigInteger(accumulatorValueRaw);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        setPublicKey(publicKey);
    }

    @Override
    protected void engineRestoreVerify(byte[] accumulatorValue) {
        this.accumulatorValueRaw = Arrays.copyOf(accumulatorValue, accumulatorValue.length);
        this.accumulatorValue = new BigInteger(accumulatorValueRaw);
    }

    @Override
    protected byte[] engineCreateWitness(byte[] element) throws AccumulatorException {
        BigInteger hash;
        try {
            hash = fullDomainHash(publicKey.getKey(), element);
        } catch (NoSuchAlgorithmException e) {
            throw new AccumulatorException(e);
        }

        BigInteger exponent = hash.modInverse(privateKey.getKey());

        return accumulatorValue.modPow(exponent, publicKey.getKey()).toByteArray();
    }

    @Override
    protected boolean engineVerify(byte[] witness, byte[] element) throws AccumulatorException {
        BigInteger hash;
        try {
            hash = fullDomainHash(publicKey.getKey(), element);
        } catch (NoSuchAlgorithmException e) {
            throw new AccumulatorException(e);
        }

        BigInteger proofAsInt = new BigInteger(witness);
        BigInteger acc_aux = proofAsInt.modPow(hash, publicKey.getKey());

        return Arrays.equals(acc_aux.toByteArray(), accumulatorValueRaw);
    }

    @Override
    protected byte[] engineGetAccumulatorValue() throws AccumulatorException {
        return Arrays.copyOf(accumulatorValueRaw, accumulatorValueRaw.length);
    }

    @Override
    protected byte[] engineGetAuxiliaryValue() throws AccumulatorException {
        return null;
    }

    @Override
    protected AccumulatorState engineGetAccumulatorState() {
        return new AccumulatorState(accumulatorValueRaw, null);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        //TODO
    }

    private void setPublicKey(PublicKey key) throws InvalidKeyException {
        if (!(key instanceof PSRSSPublicKey)) {
            throw new InvalidKeyException("The given key is not a RSSPublicKey");
        }
        publicKey = (PSRSSPublicKey) key;
    }

    private void setKeyPair(KeyPair keyPair) throws InvalidKeyException {
        if (!(keyPair.getPrivate() instanceof PSRSSPrivateKey)) {
            throw new InvalidKeyException("The given key are not a RSSPrivateKey");
        }

        setPublicKey(keyPair.getPublic());
        privateKey = (PSRSSPrivateKey) keyPair.getPrivate();

    }
}
