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

/**
 * @author Wolfgang Popp
 */
public class PSRSSKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int CERTAINTY = 40;

    private static final BigDecimal LOWER_LIMIT_FACTOR = BigDecimal.valueOf(1.071773463);
    private static final BigDecimal UPPER_LIMIT_FACTOR = BigDecimal.valueOf(1073741824);

    private SecureRandom random;
    private int keySize;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        //TODO default behaviour if initialize() was not called.
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        //TODO
        super.initialize(params, random);
    }

    @Override
    public KeyPair generateKeyPair() {
        //divide bitlength by 2 as the complete keys are supposed to have the said bitlength
        //TODO make p or q one bit larger if bitLength is not divisible by 2?
        List<BigInteger> safePrimes = new ArrayList<>();

        safePrimes.add(safePrime(keySize / 2));
        safePrimes.add(safePrime(keySize / 2));

        while (true) {
            for (BigInteger safePrimeA : safePrimes) {
                for (BigInteger safePrimeB : safePrimes) {
                    if (inRange(safePrimeA, safePrimeB)) {
                        PrivateKey privateKey = new PSRSSPrivateKey(safePrimeA.subtract(BigInteger.ONE).multiply(safePrimeB.subtract(BigInteger.ONE)));
                        PublicKey publicKey = new PSRSSPublicKey(safePrimeA.multiply(safePrimeB));
                        return new KeyPair(publicKey, privateKey);
                    }
                }
            }
            safePrimes.add(safePrime(keySize / 2));
        }
    }

    private boolean inRange(BigInteger safePrimeA, BigInteger safePrimeB) {
        BigInteger lowerLimit = LOWER_LIMIT_FACTOR.multiply(new BigDecimal(safePrimeA)).toBigInteger();
        BigInteger upperLimit = UPPER_LIMIT_FACTOR.multiply(new BigDecimal(safePrimeA)).toBigInteger();
        return safePrimeB.compareTo(lowerLimit) > 0 && safePrimeB.compareTo(upperLimit) < 0;
    }

    /**
     * Creates a safe prime number of the given bit length. A prime number <code>p</code> is safe, if p=2*q+1, where q
     * is also prime.
     *
     * @param bitLength the length of the prime number
     * @return java.math.BigInteger which is a safe prime number
     */
    private BigInteger safePrime(int bitLength) {
        BigInteger p, q;

        if (random == null) {
            random = new SecureRandom();
        }

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
