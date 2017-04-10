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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.cryptoutils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author Wolfgang Popp
 */
public final class CryptoUtils {

    private static final int CERTAINTY = 100; // BigInteger also uses 100 for its default certainty

    /**
     * Calculates a full domain hash (FDH) for the given byte array and the given maximum, where
     * <code>FDH < publicKey</code>
     *
     * @param max the maximum value of the resulting FDH
     * @param m   message for which the hash shall be calculated
     * @return a big integer representing the full domain hash
     * @throws NoSuchAlgorithmException if no SHA-512 implementation is found
     */
    public static BigInteger fullDomainHash(BigInteger max, byte[] m) throws NoSuchAlgorithmException {
        BigInteger counter = BigInteger.ZERO;
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        int digestLength = md.getDigestLength();
        int bitLength = max.bitLength();
        BigInteger fdh;

        //Calculate a sha-512 of m
        md.update(m);
        md.update(counter.toByteArray());
        byte[] shortHash = md.digest();
        byte[] largeHash = shortHash;
        counter = counter.add(BigInteger.ONE);

        //while the length of the hash is smaller than bitlength of the key, calculated more hashes
        //with increased counter and concactenate the hashes until the bitlength is bigger/equals the bitlength
        //of the bitlength of the key
        while ((largeHash.length * 8) < bitLength) {
            md.update(m);
            md.update(counter.toByteArray());
            shortHash = md.digest();

            counter = counter.add(BigInteger.ONE);

            byte[] hashConcat = new byte[largeHash.length + shortHash.length];
            System.arraycopy(largeHash, 0, hashConcat, 0, largeHash.length);
            System.arraycopy(shortHash, 0, hashConcat, largeHash.length, shortHash.length);
            largeHash = hashConcat;
        }

        // set first bit to 1. This ensures, that the BigInteger (in the next step) has the correct bitlength.
        largeHash[0] |= 0x80;

        fdh = new BigInteger(1, largeHash);
        //cut the hash to the same size as the public key
        fdh = fdh.shiftRight((largeHash.length * 8) - bitLength);

        // set last bit to 1 to ensure that the hash is odd. (Add 1 if the hash is even)
        fdh = fdh.setBit(0);

        while (fdh.compareTo(max) > 0) {
            counter = counter.add(BigInteger.ONE);
            md.update(m);
            md.update(counter.toByteArray());
            shortHash = md.digest();
            System.arraycopy(largeHash, digestLength, largeHash, 0, largeHash.length - digestLength);
            System.arraycopy(shortHash, 0, largeHash, largeHash.length - digestLength, digestLength);

            // set first bit to 1. This ensures, that the BigInteger (in the next step) has the correct bitlength.
            largeHash[0] |= 0x80;

            fdh = new BigInteger(1, largeHash);
            //cut the hash to the same size as the public key
            fdh = fdh.shiftRight((largeHash.length * 8) - bitLength);

            // set last bit to 1 to ensure that the hash is odd. (Add 1 if the hash is even)
            fdh = fdh.setBit(0);
        }

        return fdh;
    }



    /**
     * Creates a safe prime number of the given bit length. A prime number <code>p</code> is safe, if p=2*q+1, where q
     * is also prime.
     *
     * @param bitLength the length of the prime number
     * @param random the random pool used
     * @return java.math.BigInteger which is a safe prime number
     */
    public static BigInteger safePrime(int bitLength, SecureRandom random) {
        BigInteger p, q;

        q = BigInteger.probablePrime(bitLength - 1, random);
        p = q.add(q).add(BigInteger.ONE);

        while (!p.isProbablePrime(CERTAINTY)) {
            do {
                q = q.nextProbablePrime();

            } while (q.mod(BigInteger.TEN).equals(BigInteger.valueOf(7))
                    || !q.remainder(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)));

            p = q.add(q).add(BigInteger.ONE);

            while (p.bitLength() != bitLength) {
                q = BigInteger.probablePrime(bitLength - 1, random);
                p = q.add(q).add(BigInteger.ONE);
            }
        }

        return p;
    }

    //private static BigInteger safePrimeNaive(int bitLength) {
    //    BigInteger probablePrime = BigInteger.probablePrime(bitLength, new SecureRandom());

    //    while (!probablePrime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)).isProbablePrime(CERTAINTY)) {
    //        probablePrime = probablePrime.nextProbablePrime();
    //        if (probablePrime.bitLength() != bitLength) {
    //            probablePrime = BigInteger.probablePrime(bitLength, new SecureRandom());
    //        }
    //    }

    //    return probablePrime;
    //}

}
