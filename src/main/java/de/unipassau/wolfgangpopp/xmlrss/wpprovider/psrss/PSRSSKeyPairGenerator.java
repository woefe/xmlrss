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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.CryptoUtils.safePrime;


/**
 * @author Wolfgang Popp
 */
public class PSRSSKeyPairGenerator extends KeyPairGeneratorSpi {


    private static final BigDecimal LOWER_LIMIT_FACTOR = BigDecimal.valueOf(1.071773463);
    private static final BigDecimal UPPER_LIMIT_FACTOR = BigDecimal.valueOf(1073741824);

    private SecureRandom random = new SecureRandom();
    private int keySize = 2048;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {

        //TODO
        super.initialize(params, random);
    }

    @Override
    public KeyPair generateKeyPair() {
        //divide bitlength by 2 as the complete keys are supposed to have the said bitlength
        //TODO make p or q one bit larger if bitLength is not divisible by 2?
        List<BigInteger> safePrimes = new ArrayList<>();

        safePrimes.add(safePrime(keySize / 2, random));
        safePrimes.add(safePrime(keySize / 2, random));

        while (true) {
            for (BigInteger safePrimeA : safePrimes) {
                for (BigInteger safePrimeB : safePrimes) {
                    if (inRange(safePrimeA, safePrimeB)) {
                        PrivateKey privateKey = new PSRSSPrivateKey(safePrimeA.subtract(BigInteger.ONE)
                                .multiply(safePrimeB.subtract(BigInteger.ONE)));
                        PublicKey publicKey = new PSRSSPublicKey(safePrimeA.multiply(safePrimeB));
                        return new KeyPair(publicKey, privateKey);
                    }
                }
            }
            safePrimes.add(safePrime(keySize / 2, random));
        }
    }

    private boolean inRange(BigInteger safePrimeA, BigInteger safePrimeB) {
        BigInteger lowerLimit = LOWER_LIMIT_FACTOR.multiply(new BigDecimal(safePrimeA)).toBigInteger();
        BigInteger upperLimit = UPPER_LIMIT_FACTOR.multiply(new BigDecimal(safePrimeA)).toBigInteger();
        return safePrimeB.compareTo(lowerLimit) > 0 && safePrimeB.compareTo(upperLimit) < 0;
    }

}
