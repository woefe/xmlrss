package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorSpi;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author Wolfgang Popp
 */
public class PSAccumulator extends AccumulatorSpi {

    private PSRSSPrivateKey privateKey;
    private PSRSSPublicKey publicKey;
    private byte[] accumulatorValueRaw;
    private BigInteger accumulatorValue;

    @Override
    protected byte[] engineInitWitness(KeyPair keyPair, byte[]... elements) throws InvalidKeyException {
        setKeyPair(keyPair);

        SecureRandom random = new SecureRandom();
        BigInteger n = publicKey.getKey();

        int bitLength = n.bitLength();
        BigInteger digest;

        do {
            digest = new BigInteger(bitLength, random);
        } while (digest.compareTo(n) == 1 || !digest.gcd(n).equals(BigInteger.ONE));

        accumulatorValueRaw = digest.toByteArray();
        accumulatorValue = new BigInteger(accumulatorValueRaw);
        return Arrays.copyOf(accumulatorValueRaw, accumulatorValueRaw.length);
    }

    @Override
    protected void engineRestore(KeyPair keyPair, byte[] accumulatorValue) throws InvalidKeyException {
        setKeyPair(keyPair);
        this.accumulatorValueRaw = Arrays.copyOf(accumulatorValue, accumulatorValue.length);
        this.accumulatorValue = new BigInteger(accumulatorValueRaw);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey, byte[] accumulatorValue) throws InvalidKeyException {
        setPublicKey(publicKey);
        this.accumulatorValueRaw = Arrays.copyOf(accumulatorValue, accumulatorValue.length);
        this.accumulatorValue = new BigInteger(accumulatorValueRaw);
    }

    @Override
    protected byte[] engineCreateWitness(byte[] element) throws AccumulatorException {
        BigInteger hash;
        try {
            hash = fullDomainHash(publicKey, element);
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
            hash = fullDomainHash(publicKey, element);
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
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        //TODO
    }

    /**
     * Returns a full domain hash (FDH) for the given byte array and public key, where <code>FDH < publicKey</code>
     *
     * @param publicKey that is used for further crypto operations
     * @param m         message for which the hash shall be calculated
     * @return a biginteger representing the full domain hash
     * @throws NoSuchAlgorithmException
     */
    private BigInteger fullDomainHash(PSRSSPublicKey publicKey, byte[] m) throws NoSuchAlgorithmException {
        //TODO: Remove the public and only provide the bit length?
        BigInteger counter = BigInteger.ZERO;
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        int digestLength = md.getDigestLength();
        int bitLength = publicKey.getKey().bitLength();
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

        while (fdh.compareTo(publicKey.getKey()) > 0) {
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
