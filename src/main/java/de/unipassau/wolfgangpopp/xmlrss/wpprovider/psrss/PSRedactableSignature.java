package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Accumulator;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.ModificationInstruction;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableSignature extends RedactableSignatureSpi {

    private PSRSSPublicKey publicKey;
    private PSRSSPrivateKey privateKey;
    private Accumulator accumulator;
    private SecureRandom random;
    private final Set<byte[]> parts = new HashSet<>();
    private KeyPair keyPair;

    PSRedactableSignature(Accumulator accumulator) {
        this.accumulator = accumulator;
    }

    protected void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
        engineInitSign(keyPair, new SecureRandom());
    }

    protected void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        setKeyPair(keyPair);
        this.random = random;
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        setPublicKey(publicKey);
    }

    protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        setPublicKey(publicKey);
    }

    protected void engineInitMerge(PublicKey publicKey) throws InvalidKeyException {
        setPublicKey(publicKey);
    }

    @Override
    protected void engineInitUpdate(KeyPair keyPair) throws InvalidKeyException {
        setKeyPair(keyPair);
    }

    //TODO admissible is ignored
    protected void engineAddPart(byte[] part, boolean admissible) throws SignatureException {
        parts.add(part);
    }

    protected SignatureOutput engineSign() throws SignatureException {
        final byte[] acc;
        try {
            acc = accumulator.initWitness(keyPair, parts.toArray(new byte[][]{}));
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        }

        final byte[] tag = new byte[publicKey.getKey().bitLength()];
        random.nextBytes(tag);

        final byte[] proofOfTag;
        try {
            proofOfTag = accumulator.createWitness(tag);
        } catch (AccumulatorException e) {
            throw new SignatureException(e);
        }

        PSSignatureOutput.Builder builder = new PSSignatureOutput.Builder(tag, proofOfTag, acc);

        Function<byte[], PSSignatureOutput.SignedElement> signFunction = new Function<byte[], PSSignatureOutput.SignedElement>() {
            @Override
            public PSSignatureOutput.SignedElement execute(byte[] argument) throws Exception {
                return signElement(tag, argument);
            }
        };

        builder.addAll(map(signFunction, parts));

        return builder.build();
    }

    private PSSignatureOutput.SignedElement signElement(byte[] tag, byte[] element) throws AccumulatorException {

        byte[] valueConcatTag = new byte[tag.length + element.length];
        System.arraycopy(element, 0, valueConcatTag, 0, element.length);
        System.arraycopy(tag, 0, valueConcatTag, element.length - 1, tag.length);
        return new PSSignatureOutput.SignedElement(element, accumulator.createWitness(valueConcatTag));
    }

    protected boolean engineVerify(SignatureOutput signature) throws SignatureException {
        return false;
    }

    protected SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
        return null;
    }

    protected SignatureOutput engineMerge(SignatureOutput signature1, SignatureOutput signature2) throws SignatureException {
        return null;
    }

    @Override
    protected SignatureOutput engineUpdate(SignatureOutput signature) throws SignatureException {
        return null;
    }

    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {

    }

    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void setPublicKey(PublicKey key) throws InvalidKeyException {
        if (!(key instanceof PSRSSPublicKey)) {
            throw new InvalidKeyException("The given key is not a RSSPublicKey");
        }
        publicKey = (PSRSSPublicKey) key;
    }

    private void setKeyPair(KeyPair keyPair) throws InvalidKeyException {
        if (!(keyPair.getPrivate() instanceof PSRSSPrivateKey)) {
            throw new InvalidKeyException("The given key is not a RSSPrivateKey");
        }
        setPublicKey(keyPair.getPublic());
        privateKey = (PSRSSPrivateKey) keyPair.getPrivate();
        this.keyPair = keyPair;

    }

    /**
     * Applies the given function to every element of the given collection and returns a Collection of the results.
     *
     * @param function   the function which is applied to every element of collection
     * @param collection the elements
     * @param <E>        Input (argument) type
     * @param <R>        Result type
     * @return a collection of results of the function
     * @throws SignatureException
     */
    private <E, R> Collection<R> map(final Function<E, R> function, Iterable<E> collection) throws SignatureException {
        ForkJoinPool pool = new ForkJoinPool(Runtime.getRuntime().availableProcessors());
        Collection<Callable<R>> tasks = new LinkedList<>();

        for (final E item : collection) {
            tasks.add(new Callable<R>() {
                @Override
                public R call() throws Exception {
                    return function.execute(item);
                }
            });
        }

        List<Future<R>> futures = pool.invokeAll(tasks);
        Collection<R> results = new ArrayList<>(futures.size());

        for (Future<R> future : futures) {
            if (!future.isCancelled()) {
                try {
                    results.add(future.get());
                } catch (InterruptedException | ExecutionException e) {
                    throw new SignatureException(e);
                }
            } else {
                throw new SignatureException("Parallel execution failed");
            }
        }

        pool.shutdown();

        return results;
    }

    /**
     * The function Interface describes a function of the following type:
     * f: E --> R, x |--> f(x)
     *
     * @param <E> the type of the argument of the function
     * @param <R> the type of the result
     */
    private interface Function<E, R> {
        R execute(E argument) throws Exception;
    }

    public static final class RSSwithPSA extends PSRedactableSignature {
        public RSSwithPSA() throws NoSuchAlgorithmException {
            super(Accumulator.getInstance("PSA"));
        }
    }
}
