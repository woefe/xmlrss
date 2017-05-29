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
 * Sign:
 * <ol>
 *     <li>{@link #initSign(KeyPair)}</li>
 *     <li>{@link #addPart(byte[])}</li>
 *     <li>{@link #sign()}</li>
 * </ol>
 *
 * Verify:
 * <ol>
 *     <li>{@link #initVerify(PublicKey)}</li>
 *     <li>{@link #verify(SignatureOutput)}</li>
 * </ol>
 *
 * Redact:
 * <ol>
 *     <li>{@link #initRedact(PublicKey)}</li>
 *     <li>{@link #addIdentifier(Identifier)}</li>
 *     <li>{@link #redact(SignatureOutput)}</li>
 * </ol>
 *
 * Update:
 * <ol>
 *     <li>{@link #initUpdate(KeyPair)}</li>
 *     <li>{@link #addPart(byte[])}</li>
 *     <li>{@link #update(SignatureOutput)}</li>
 * </ol>
 *
 * Merge:
 * <ol>
 *     <li>{@link #initMerge(PublicKey)}</li>
 *     <li>{@link #merge(SignatureOutput, SignatureOutput)}</li>
 * </ol>
 *
 * @author Wolfgang Popp
 */
public abstract class RedactableSignature {

    //TODO Debug mode

    private Provider provider;
    private String algorithm;
    private STATE state;
    private final RedactableSignatureSpi engine;
    private static final String TYPE = "RedactableSignature";

    private enum STATE {
        UNINITIALIZED, SIGN, REDACT, VERIFY, UPDATE, MERGE
    }

    /**
     * Constructs a RedactableSignature object with the specified algorithm name.
     *
     * @param algorithm the algorithm of this redactable signature
     */
    protected RedactableSignature(RedactableSignatureSpi engine, String algorithm) {
        this.algorithm = algorithm;
        this.engine = engine;
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
        NoSuchAlgorithmException failure = new NoSuchAlgorithmException(algorithm +
                "RedactableSignature not available");
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
        engine.engineInitSign(keyPair);
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
        engine.engineInitSign(keyPair, random);
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
        engine.engineInitVerify(publicKey);
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
        engine.engineInitRedact(publicKey);
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
        engine.engineInitMerge(publicKey);
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
        engine.engineInitUpdate(keyPair);
    }

    /**
     * Adds a new message part to be signed.
     * <p>
     * Every message part added with this method can later be redacted if the given boolean flag is set to true. Note
     * that the returned identifier might not identify the added element any more when redactions took place, because
     * indices of the message elements might change because of redactions.
     *
     * @param part the part to be added
     * @param isRedactable a boolean indicating whether the given part can be redacted from the signed message.
     * @return an Identifier that identifies the added element in the SignatureOutput
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly or if this
     *                                      redactable signature algorithm is unable to process the given element.
     */
    public final Identifier addPart(byte[] part, boolean isRedactable) throws RedactableSignatureException {
        if (state == STATE.SIGN || state == STATE.UPDATE) {
            return engine.engineAddPart(part, isRedactable);
        }
        throw new RedactableSignatureException("not initialized for signing or updating");
    }

    /**
     * Adds a new redactable message part.
     * <p>
     * This method is equivalent to <code>addPart(part, true)</code>.
     *
     * @param part the part to be added
     * @return an Identifier that identifies the added element in the SignatureOutput
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly or if this
     *                                      redactable signature algorithm is unable to process the given element.
     */
    public final Identifier addPart(byte[] part) throws RedactableSignatureException {
        return addPart(part, true);
    }

    /**
     * Identifies an element for redaction.
     *
     * @param identifier the identifier as returned by {@link #addPart(byte[])} or newly created
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly or if this
     *                                      redactable signature algorithm is unable to process the given identifier.
     */
    public final void addIdentifier(Identifier identifier) throws RedactableSignatureException {
        if (state == STATE.REDACT) {
            engine.engineAddIdentifier(identifier);
        } else {
            throw new RedactableSignatureException("not initialized for redaction");
        }
    }

    /**
     * Signs the elements that were added via a {@link #addPart(byte[]) addPart} method.
     * <p>
     * A call of this method resets this signature object to the initial state, which is the state it was in after a
     * call of {@link #initSign(KeyPair)}. That is, the object is reset and available to generate another signature from
     * the same signer.
     *
     * @return the SignatureOutput that contains the signature of the added elements.
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this
     *                                      redactable signature algorithm cannot process the elements to be signed.
     */
    public final SignatureOutput sign() throws RedactableSignatureException {
        if (state == STATE.SIGN) {
            return engine.engineSign();
        }
        throw new RedactableSignatureException("not initialized for signing");
    }

    /**
     * Verifies the given SignatureOutput.
     * <p>
     * The signature output already contains the message. Therefore, the <code>addPart()</code> method must not be
     * called for verification.
     * <p>
     * A call of this method resets this signature object to the initial state, which is the state it was in after a
     * call of {@link #initVerify(PublicKey)}. That is, the object is reset and available to verify another signature
     * from the same identity whose public key was set via {@link #initVerify(PublicKey)}.
     *
     * @param signature the signature to be verified
     * @return true if the signature verifies, false otherwise
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this
     *                                      redactable signature algorithm cannot process the elements to be verified.
     */
    public final boolean verify(SignatureOutput signature) throws RedactableSignatureException {
        if (state == STATE.VERIFY) {
            return engine.engineVerify(signature);
        }
        throw new RedactableSignatureException("not initialized for verification");
    }

    /**
     * Redacts the elements that were added via a {@link #addIdentifier(Identifier)} method from the given
     * SignatureOutput.
     * <p>
     * A call of this method resets this signature object to the initial state, which is the state it was in after a
     * call of {@link #initRedact(PublicKey)}. That is, the object is reset and available to redact another signature
     * from the same identity whose public key was set via {@link #initRedact(PublicKey)}.
     *
     * @param signature the signature which should be redacted
     * @return the redacted SignatureOutput
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this
     *                                      redactable signature algorithm cannot process the elements to be redacted.
     */
    public final SignatureOutput redact(SignatureOutput signature) throws RedactableSignatureException {
        if (state == STATE.REDACT) {
            return engine.engineRedact(signature);
        }
        throw new RedactableSignatureException("not initialized for redaction");
    }

    /**
     * Merges the two given signatures.
     * <p>
     * Only different redacted versions of the same original signature can be merged again.
     * <p>
     * A call of this method resets this signature object to the initial state, which is the state it was in after a
     * call of {@link #initMerge(PublicKey)}. That is, the object is reset and available to redact another signature
     * from the same identity whose public key was set via {@link #initMerge(PublicKey)}.
     *
     * @param signature1 a redacted version of a signature output
     * @param signature2 another redacted version of the same original signature output as <code>signature1</code>
     * @return the merged SignatureOutput of signature1 and signature2
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if the
     *                                      two signatures cannot be merged
     */
    public SignatureOutput merge(SignatureOutput signature1, SignatureOutput signature2)
            throws RedactableSignatureException {

        if (state == STATE.MERGE) {
            return engine.engineMerge(signature1, signature2);
        }
        throw new RedactableSignatureException("not initialized for merging");
    }

    /**
     * Adds the elements that were added via a {@link #addPart(byte[]) addPart} method to the given signature.
     * <p>
     * A call of this method resets this signature object to the initial state, which is the state it was in after a
     * call of {@link #initUpdate(KeyPair)}. That is, the object is reset and available to update another signature from
     * the same signer.
     *
     * @param signature the signature which should be updated
     * @return the updated SignatureOutput object
     * @throws RedactableSignatureException if this RedactableSignature object is not initialized properly. Or if this
     *                                      redactable signature algorithm cannot process the elements to be updated.
     */
    public SignatureOutput update(SignatureOutput signature) throws RedactableSignatureException {
        if (state == STATE.UPDATE) {
            return engine.engineUpdate(signature);
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
        return engine.engineGetParameters();
    }

    /**
     * Initializes this redactable signature with the specified parameter set.
     *
     * @param parameters the parameters
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this algorithm
     */
    public final void setParameters(AlgorithmParameters parameters) throws InvalidAlgorithmParameterException {
        engine.engineSetParameters(parameters);
    }

    @Override
    public String toString() {
        return "RedactableSignature (Algorithm: " + getAlgorithm() + ", Initialization state: " + state + ")";
    }

    static class Delegate extends RedactableSignature {
        Delegate(RedactableSignatureSpi engine, String algorithm) {
            super(engine, algorithm);
        }
    }
}
