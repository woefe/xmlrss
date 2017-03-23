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

import sun.security.jca.GetInstance;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.List;

/**
 * The RedactableSignature class provides applications the functionality of a digital redactable signature. Redactable
 * signatures allow to removed parts from a signed message without invalidating the signature of the message.
 * <p>
 * A RedactableSignature object can be used to generate, verify, redact, merge or update redactable signatures. Note
 * that redactable signature schemes exist, which do not support merging or updating signatures.
 * <p>
 * A RedactableSignature object is used in three phases:
 * <ol>
 * <li> Initialization via: {@link #initSign(KeyPair) initSign}, {@link #initVerify(PublicKey) initVerify},
 * {@link #initRedact(PublicKey) initRedact}, {@link #initMerge(PublicKey) initMerge},
 * {@link #initUpdate(KeyPair) initUpdate}
 * <li> Adding the (message-)parts that will be signed, verified redacted by the RedactableSignature object, using
 * {@link #addPart(byte[], boolean) addPart}.
 * <li> Executing the the operation which the RedactableSignature object was initialized for. See
 * {@link #sign() sign}, {@link #initVerify(PublicKey) verify},
 * {@link #redact(SignatureOutput) redact},
 * {@link #merge(SignatureOutput, SignatureOutput) merge},
 * {@link #update(SignatureOutput) update}
 * </ol>
 *
 * @author Wolfgang Popp
 */
public abstract class RedactableSignature extends RedactableSignatureSpi {

    //TODO Debug mode

    private Provider provider;
    private String algorithm;
    private STATE state;
    private static final String TYPE = "RedactableSignature";

    private enum STATE {
        UNINITIALIZED, SIGN, REDACT, VERIFY, UPDATE, MERGE
    }

    /**
     * Constructs a RedactableSignature object with the specified algorithm name.
     *
     * @param algorithm the algorithm of this redactable signature
     */
    protected RedactableSignature(String algorithm) {
        this.algorithm = algorithm;
        this.state = STATE.UNINITIALIZED;
    }

    /**
     * Returns a RedactableSignature object that implements the specified redactable signature algorithm.
     * <p>
     * This method traverses the list of registered security Providers, starting with the most preferred Provider. A new
     * RedactableSignature object encapsulating the RedactableSignatureSpi implementation from the first Provider that
     * supports the specified algorithm is returned.
     * <p>
     * Note that the list of registered providers may be retrieved via the <code>Security.getProviders()</code> method.
     *
     * @param algorithm the name of the requested algorithm
     * @return a new RedactableSignature object.
     * @throws NoSuchAlgorithmException if no Provider supports a RedactableSignature implementation for the specified
     *                                  algorithm.
     */
    public static RedactableSignature getInstance(String algorithm) throws NoSuchAlgorithmException {
        NoSuchAlgorithmException failure = new NoSuchAlgorithmException(algorithm + "RedactableSignature not available");
        List<Provider.Service> services = GetInstance.getServices(TYPE, algorithm);

        for (Provider.Service service : services) {
            try {
                GetInstance.Instance instance = GetInstance.getInstance(service, RedactableSignatureSpi.class);
                return getInstance(instance, algorithm);
            } catch (NoSuchAlgorithmException e) {
                failure = e;
            }
        }
        throw failure;
    }

    /**
     * Returns a RedactableSignature object that implements the specified redactable signature algorithm.
     * <p>
     * A new RedactableSignature object encapsulating the RedactableSignatureSpi implementation from the specified
     * provider is returned. The specified provider must be registered in the security provider list.
     * <p>
     * Note that the list of registered providers may be retrieved via the <code>Security.getProviders()</code> method.
     *
     * @param algorithm the name of the requested algorithm
     * @param provider  the name of the provider
     * @return a new RedactableSignature object.
     * @throws NoSuchProviderException  if the specified provider is not registered in the security provider list.
     * @throws NoSuchAlgorithmException if a RedactableSignatureSpi implementation for the specified algorithm is not
     *                                  available from the specified provider.
     */
    public static RedactableSignature getInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance(TYPE,
                RedactableSignatureSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    /**
     * Returns a RedactableSignature object that implements the specified redactable signature algorithm.
     * <p>
     * A new RedactableSignature object encapsulating the RedactableSignatureSpi implementation from the specified
     * provider object is returned. Note that the specified provider object does not have to be registered in the
     * security provider list.
     *
     * @param algorithm the name of the requested algorithm
     * @param provider  the provider
     * @return a new RedactableSignature object.
     * @throws NoSuchAlgorithmException if a RedactableSignatureSpi implementation for the specified algorithm is not
     *                                  available from the specified provider.
     */
    public static RedactableSignature getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        GetInstance.Instance instance = GetInstance.getInstance(TYPE,
                RedactableSignatureSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    private static RedactableSignature getInstance(GetInstance.Instance instance, String algorithm) {
        RedactableSignature sig;
        if (instance.impl instanceof RedactableSignature) {
            sig = (RedactableSignature) instance.impl;
            sig.algorithm = algorithm;
        } else {
            RedactableSignatureSpi spi = (RedactableSignatureSpi) instance.impl;
            sig = new Delegate(spi, algorithm);
        }
        sig.provider = instance.provider;
        return sig;
    }

    /**
     * Returns the {@link Provider} of this RedactableSignature object
     *
     * @return the provider of this RedactableSignature object
     */
    public final Provider getProvider() {
        return this.provider;
    }

    /**
     * Initializes this object for signing.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableSignature.
     *
     * @param keyPair the keypair of the identity whose signature is going to be generated.
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this RedactableSignature
     *                             object.
     */
    public final void initSign(KeyPair keyPair) throws InvalidKeyException {
        state = STATE.SIGN;
        engineInitSign(keyPair);
    }

    /**
     * Initializes this object for signing.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableSignature.
     *
     * @param keyPair the keypair of the identity whose signature is going to be generated.
     * @param random  the source of randomness for this signature
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this RedactableSignature
     *                             object.
     */
    public final void initSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        state = STATE.SIGN;
        engineInitSign(keyPair, random);
    }

    /**
     * Initializes this object for verification.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableSignature.
     *
     * @param publicKey the public key of the identity whose signature is going to be verified.
     * @throws InvalidKeyException if the given public key is inappropriate for initializing this RedactableSignature
     *                             object.
     */
    public final void initVerify(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.VERIFY;
        engineInitVerify(publicKey);
    }

    /**
     * Initializes this object for redaction.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableSignature.
     *
     * @param publicKey the public key of the identity whose signature is going to be redacted.
     * @throws InvalidKeyException if the given public key is inappropriate for initializing this RedactableSignature
     *                             object.
     */
    public final void initRedact(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.REDACT;
        engineInitRedact(publicKey);
    }

    /**
     * Initializes this object for merging. Note that not all redactable signature implementations support mergeing. In
     * this case a {@link UnsupportedOperationException} is thrown.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableSignature.
     *
     * @param publicKey the public key of the identity whose signatures are going to be merged.
     * @throws InvalidKeyException if the given public key is inappropriate for initializing this RedactableSignature
     *                             object.
     */
    public void initMerge(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.MERGE;
        engineInitMerge(publicKey);
    }

    /**
     * Initializes this object for updating. Note that not all redactable signature implementations support updating. In
     * this case a {@link UnsupportedOperationException} is thrown.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableSignature.
     *
     * @param keyPair the keypair of the identity whose signature is going to be updated.
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing this RedactableSignature
     *                             object.
     */
    public void initUpdate(KeyPair keyPair) throws InvalidKeyException {
        state = STATE.UPDATE;
        engineInitUpdate(keyPair);
    }

    /**
     * @param part
     * @param isRedactable a boolean indicating whether the given part can be redacted from the signed message.
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly or if this redactable
     *                            signature algorithm is unable to process the given element.
     */
    public final void addPart(byte[] part, boolean isRedactable) throws RedactableSignatureException {
        if (state != STATE.UNINITIALIZED) {
            engineAddPart(part, isRedactable);
        } else {
            throw new RedactableSignatureException("not initialized");
        }
    }

    public final void addPart(byte[] part) throws RedactableSignatureException {
        addPart(part, true);
    }

    public final void addParts(byte[]... parts) throws RedactableSignatureException {
        for (byte[] part : parts) {
            addPart(part);
        }
    }

    /**
     * Signs the elements that were added via a {@link #addPart(byte[]) addPart} method against.
     *
     * @return the SignatureOutput that contains the signature of the added elements.
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this redactable
     *                            signature algorithm cannot process the elements to be signed.
     */
    public final SignatureOutput sign() throws RedactableSignatureException {
        if (state == STATE.SIGN) {
            return engineSign();
        }
        throw new RedactableSignatureException("not initialized for signing");
    }

    /**
     * Verifies the elements that were added via a {@link #addPart(byte[]) addPart} method against the given signature.
     *
     * @param signature the signature to be verified
     * @return true if the signature verifies, false otherwise
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this redactable
     *                            signature algorithm cannot process the elements to be verified.
     */
    public final boolean verify(SignatureOutput signature) throws RedactableSignatureException {
        if (state == STATE.VERIFY) {
            return engineVerify(signature);
        }
        throw new RedactableSignatureException("not initialized for verification");
    }

    /**
     * Redacts the elements that were added via a {@link #addPart(byte[]) addPart} method from the given
     * SignatureOutput
     *
     * @param signature the signature which should be redacted
     * @return the redacted SignatureOutput
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this redactable
     *                            signature algorithm cannot process the elements to be redacted.
     */
    public final SignatureOutput redact(SignatureOutput signature) throws RedactableSignatureException {
        if (state == STATE.REDACT) {
            return engineRedact(signature);
        }
        throw new RedactableSignatureException("not initialized for redaction");
    }

    /**
     * Merges the two given signatures. Only different redacted versions of the same original signature can be merged
     * again.
     *
     * @param signature1 a redacted version of a signature output
     * @param signature2 another redacted version of the same original signature output as <code>signature1</code>
     * @return the merged SignatureOutput of signature1 and signature2
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if the two
     *                            signatures cannot be merged
     */
    public SignatureOutput merge(SignatureOutput signature1, SignatureOutput signature2) throws RedactableSignatureException {
        if (state == STATE.MERGE) {
            return engineMerge(signature1, signature2);
        }
        throw new RedactableSignatureException("not initialized for merging");
    }

    /**
     * Adds the elements that were added via a {@link #addPart(byte[]) addPart} method to the given signature.
     *
     * @param signature the signature which should be updated
     * @return teh updated SignatureOutput object
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this redactable
     *                            signature algorithm cannot process the elements to be updated.
     */
    public SignatureOutput update(SignatureOutput signature) throws RedactableSignatureException {
        if (state == STATE.UPDATE) {
            return engineUpdate(signature);
        }
        throw new RedactableSignatureException("not initialized for updating");
    }

    /**
     * Returns the name of the algorithm for this redactable signature object.
     *
     * @return the name of the algorithm for this redactable signature object
     */
    public final String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * Returns the parameters used with this RedactableSignature object.
     * <p>
     * The returned parameters may be the same that were used to initialize this redactable signature, or may contain a
     * combination of default and random parameter values used by the underlying redactable signature implementation if
     * this redactable signature requires algorithm parameters but was not initialized with any.
     *
     * @return the parameters used with this redactable signature or null if no parameters are used
     */
    public final AlgorithmParameters getParameters() {
        return engineGetParameters();
    }

    /**
     * Initializes this redactable signature with the specified parameter set.
     *
     * @param parameters the parameters
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this algorithm
     */
    public final void setParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        engineSetParameters(parameters);
    }

    @Override
    public String toString() {
        return "RedactableSignature (Algorithm: " + getAlgorithm() + ", Initialization state: " + state + ")";
    }

    static class Delegate extends RedactableSignature {

        private RedactableSignatureSpi rssSPI;

        Delegate(RedactableSignatureSpi spi, String algorithm) {
            super(algorithm);
            this.rssSPI = spi;
        }

        @Override
        protected void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
            rssSPI.engineInitSign(keyPair);
        }

        @Override
        protected void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
            rssSPI.engineInitSign(keyPair, random);
        }

        @Override
        protected void engineAddPart(byte[] part, boolean admissible) throws RedactableSignatureException {
            rssSPI.engineAddPart(part, admissible);
        }

        @Override
        protected SignatureOutput engineSign() throws RedactableSignatureException {
            return rssSPI.engineSign();
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitVerify(publicKey);
        }

        @Override
        protected boolean engineVerify(SignatureOutput signature) throws RedactableSignatureException {
            return rssSPI.engineVerify(signature);
        }

        @Override
        protected void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitRedact(publicKey);
        }

        @Override
        protected void engineInitMerge(PublicKey publicKey) throws InvalidKeyException {
            rssSPI.engineInitMerge(publicKey);
        }

        @Override
        protected void engineInitUpdate(KeyPair keyPair) throws InvalidKeyException {
            rssSPI.engineInitUpdate(keyPair);
        }

        @Override
        protected SignatureOutput engineRedact(SignatureOutput signature) throws RedactableSignatureException {
            return rssSPI.engineRedact(signature);
        }

        @Override
        protected SignatureOutput engineMerge(SignatureOutput signature1, SignatureOutput signature2) throws RedactableSignatureException {
            return rssSPI.engineMerge(signature1, signature2);
        }

        @Override
        protected SignatureOutput engineUpdate(SignatureOutput original) throws RedactableSignatureException {
            return rssSPI.engineUpdate(original);
        }

        @Override
        protected void engineSetParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
            rssSPI.engineSetParameters(parameters);
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            return rssSPI.engineGetParameters();
        }
    }
}
