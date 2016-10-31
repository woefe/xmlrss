package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.*;

import java.security.*;
import java.util.*;
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
            public PSSignatureOutput.SignedElement execute(byte[] element) throws Exception {
                return signPart(element, tag);
            }
        };

        builder.addAll(map(signFunction, parts));

        return builder.build();
    }

    private PSSignatureOutput.SignedElement signPart(byte[] element, byte[] tag) throws AccumulatorException {
        return new PSSignatureOutput.SignedElement(accumulator.createWitness(concat(tag, element)), element);
    }

    private byte[] concat(byte[] first, byte[] second) {
        byte[] concat = new byte[first.length + second.length];
        System.arraycopy(first, 0, concat, 0, first.length);
        System.arraycopy(second, 0, concat, second.length - 1, second.length);
        return concat;
    }

    protected boolean engineVerify(SignatureOutput signature) throws SignatureException {
        PSSignatureOutput sig;
        if (!(signature instanceof PSSignatureOutput)) {
            throw new SignatureException("bad signature type");
        }
        sig = ((PSSignatureOutput) signature);
        try {
            accumulator.initVerify(publicKey, sig.getAccumulator());
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        }

        final byte tag[] = sig.getTag();

        Function<PSSignatureOutput.SignedElement, Boolean> verifyFunction
                = new Function<PSSignatureOutput.SignedElement, Boolean>() {

            @Override
            public Boolean execute(PSSignatureOutput.SignedElement argument) throws Exception {
                byte[] proof = argument.getProof();
                byte[] value = argument.getElement();
                return accumulator.verify(proof, concat(tag, value));
            }
        };

        Collection<Boolean> results = map(verifyFunction, sig);

        try {
            return !results.contains(false) && accumulator.verify(sig.getProofOfTag(), sig.getTag());
        } catch (AccumulatorException e) {
            throw new SignatureException(e);
        }
    }

    protected SignatureOutput engineRedact(SignatureOutput signature, ModificationInstruction mod) throws SignatureException {
        //verifySignature(key, original);

        if (!(signature instanceof PSSignatureOutput)) {
            throw new SignatureException("bad signature type");
        }

        if (!(mod instanceof PSModificationInstruction)) {
            throw new SignatureException("bad signature type");
        }

        PSSignatureOutput sig = (PSSignatureOutput) signature;
        PSModificationInstruction psMod = (PSModificationInstruction) mod;

        if (!sig.containsAll(psMod)) {
            throw new IllegalArgumentException("Redact Set is not a subset of the original set");
        }

        PSSignatureOutput.Builder builder = new PSSignatureOutput.Builder(
                sig.getTag(), sig.getProofOfTag(), sig.getAccumulator());

        for (PSSignatureOutput.SignedElement signedElement : sig) {
            if (!psMod.contains(signedElement.getElement())) {
                builder.add(signedElement);
            }
        }

        return builder.build();
    }

    protected SignatureOutput engineMerge(SignatureOutput signature1, SignatureOutput signature2) throws SignatureException {
        //verifySignature(key, s);
        //verifySignature(key, t);

        if (!(signature1 instanceof PSSignatureOutput)) {
            throw new SignatureException("bad signature type");
        }

        if (!(signature2 instanceof PSSignatureOutput)) {
            throw new SignatureException("bad signature type");
        }

        PSSignatureOutput psSignature1 = (PSSignatureOutput) signature1;
        PSSignatureOutput psSignature2 = (PSSignatureOutput) signature2;

        if (!Arrays.equals(psSignature1.getTag(), psSignature2.getTag())) {
            throw new SignatureException("the tags of the given signatures differ");
        }

        PSSignatureOutput.Builder builder = new PSSignatureOutput.Builder(psSignature1);
        for (PSSignatureOutput.SignedElement signedElement : psSignature2) {
            builder.add(signedElement);
        }

        return builder.build();
    }

    @Override
    protected SignatureOutput engineUpdate(SignatureOutput original) throws SignatureException {
        //verifySignature(keyPair.getPublic(), original);

        if (!(original instanceof PSSignatureOutput)) {
            throw new SignatureException("bad signature type");
        }

        PSSignatureOutput psSig = (PSSignatureOutput) original;

        if (!psSig.isDisjoint(parts)) {
            throw new IllegalArgumentException("Redact Set and this set are not disjoint");
        }

        PSSignatureOutput.Builder builder = new PSSignatureOutput.Builder(psSig);
        for (byte[] part : parts) {
            try {
                builder.add( signPart(part, psSig.getTag()));
            } catch (AccumulatorException e) {
                throw new SignatureException(e);
            }
        }

        return builder.build();
    }

    protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        //TODO No parameters needed
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
