/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2017 Wolfgang Popp
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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss;

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
 * The BPAccumulator implements the accumulator scheme proposed by Barić and Pfitzmann and adjusted in
 * https://www.fim.uni-passau.de/fileadmin/files/forschung/mip-berichte/MIP_1210.pdf.
 *
 * @author Wolfgang Popp
 */
public class BPAccumulator extends AccumulatorSpi {

    private BigInteger publicParm;
    private BigInteger accumulatorValue;
    private BigInteger startValue;
    private byte[][] elements;
    private SecureRandom random;

    @Override
    protected void engineInitWitness(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        checkAndSetParm(keyPair);
        this.random = random;
    }

    @Override
    protected void engineDigest(byte[]... elements) throws AccumulatorException {
        do {
            startValue = new BigInteger(publicParm.bitLength(), random);
        } while (startValue.compareTo(publicParm) == 1 || !startValue.gcd(publicParm).equals(BigInteger.ONE));

        BigInteger exponent = BigInteger.ONE;

        for (byte[] element : elements) {
            try {
                exponent = exponent.multiply(fullDomainHash(publicParm, element));
            } catch (NoSuchAlgorithmException e) {
                throw new AccumulatorException(e);
            }
        }

        accumulatorValue = startValue.modPow(exponent, publicParm);
        this.elements = elements;
    }

    @Override
    protected void engineRestoreWitness(byte[] accumulatorValue, byte[] auxiliaryValue, byte[]... elements)
            throws AccumulatorException {

        this.accumulatorValue = new BigInteger(accumulatorValue);
        this.startValue = new BigInteger(auxiliaryValue);
        this.elements = elements;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof BPPublicKey)) {
            throw new InvalidKeyException("The given key is not a BPKey");
        }
        publicParm = ((BPPublicKey) publicKey).getKey();
    }

    @Override
    protected void engineRestoreVerify(byte[] accumulatorValue) {
        this.accumulatorValue = new BigInteger(accumulatorValue);
    }

    @Override
    protected byte[] engineCreateWitness(byte[] element) throws AccumulatorException {
        BigInteger exponent = BigInteger.ONE;

        for (byte[] bytes : elements) {
            if (!Arrays.equals(bytes, element)) {
                try {
                    exponent = exponent.multiply(fullDomainHash(publicParm, bytes));
                } catch (NoSuchAlgorithmException e) {
                    throw new AccumulatorException(e);
                }
            }
        }
        return startValue.modPow(exponent, publicParm).toByteArray();
    }

    @Override
    protected boolean engineVerify(byte[] witness, byte[] element) throws AccumulatorException {
        BigInteger intWitness = new BigInteger(witness);
        try {
            BigInteger intElement = fullDomainHash(publicParm, element);
            return intWitness.modPow(intElement, publicParm).equals(accumulatorValue);
        } catch (NoSuchAlgorithmException e) {
            throw new AccumulatorException(e);
        }
    }

    @Override
    protected byte[] engineGetAccumulatorValue() throws AccumulatorException {
        return accumulatorValue.toByteArray();
    }

    @Override
    protected byte[] engineGetAuxiliaryValue() throws AccumulatorException {
        return startValue.toByteArray();
    }

    @Override
    protected AccumulatorState engineGetAccumulatorState() throws AccumulatorException {
        return new AccumulatorState(accumulatorValue.toByteArray(), startValue.toByteArray(), elements);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }

    private void checkAndSetParm(KeyPair keyPair) throws InvalidKeyException {
        if (!(keyPair.getPublic() instanceof BPPublicKey) || !(keyPair.getPrivate() instanceof BPPrivateKey)) {
            throw new InvalidKeyException("The given key pair is not a BPKeyPair");
        }
        this.publicParm = ((BPPublicKey) keyPair.getPublic()).getKey();
    }

}
