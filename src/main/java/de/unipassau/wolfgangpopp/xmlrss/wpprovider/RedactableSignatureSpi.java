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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * This class defines the Service Provider Interface for the {@link RedactableSignature} class.
 * <p>
 * All abstract methods in this class must be implemented by cryptographic services providers who wish to supply the
 * implementation of a particular redactable signature algorithm.
 *
 * @author Wolfgang Popp
 */
public abstract class RedactableSignatureSpi {

    /**
     * Initializes this redactable signature engine for signing.
     *
     * @param keyPair the keypair of the identity whose signature will be generated
     * @throws InvalidKeyException if the key is not suitable for signing (e.g. bad encoding, missing parameters, ...)
     */
    protected abstract void engineInitSign(KeyPair keyPair) throws InvalidKeyException;

    /**
     * Initializes this redactable signature engine for signing with the specified source of randomness and key pair.
     *
     * @param keyPair the keypair of the identity whose signature will be generated
     * @param random  the source of randomness
     * @throws InvalidKeyException if the key is not suitable for signing (e.g. bad encoding, missing parameters, ...)
     */
    protected abstract void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException;

    /**
     * Initializes this redactable signature engine for verification.
     *
     * @param publicKey the public key of the identity whose signature is going to be verified
     * @throws InvalidKeyException if the key is not suitable for verification (e.g. bad encoding, missing parameters, ...)
     */
    protected abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    /**
     * Initializes this redactable signature engine for redaction.
     *
     * @param publicKey the public key of the identity whose signature is going to be redacted
     * @throws InvalidKeyException if the key is not suitable for redaction (e.g. bad encoding, missing parameters, ...)
     */
    protected abstract void engineInitRedact(PublicKey publicKey) throws InvalidKeyException;

    /**
     * Initializes this redactable signature engine for merging.
     * <p>
     * Overriding this method is optional, since not all redactable signature schemes support merging. The default
     * implementation throws an <code>UnsupportedOperationException</code>.
     *
     * @param publicKey the public key of the identity whose signatures are going to be merged
     * @throws InvalidKeyException if the key is not suitable for merging (e.g. bad encoding, missing parameters, ...)
     */
    protected void engineInitMerge(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support merging");
    }

    /**
     * Initializes this redactable signature engine for updating.
     * <p>
     * Overriding this method is optional, since not all redactable signature schemes support updating. The default
     * implementation throws an <code>UnsupportedOperationException</code>.
     *
     * @param keyPair the keypair of the identity whose signature will be updated
     * @throws InvalidKeyException if the key is not suitable for updating (e.g. bad encoding, missing parameters, ...)
     */
    protected void engineInitUpdate(KeyPair keyPair) throws InvalidKeyException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support updating");
    }

    /**
     * Adds a message part that is going to be signed.
     *
     * @param part         the message part
     * @param isRedactable a boolean indicating whether the given part can be redacted from the signed message.
     * @return an Identifier that identifies the added element in the SignatureOutput
     * @throws RedactableSignatureException if the given part cannot be processed. E.g. a duplicate in set based
     *                                      algorithm
     */
    protected abstract Identifier engineAddPart(byte[] part, boolean isRedactable) throws RedactableSignatureException;

    /**
     * Identifies an element that is going to be redacted.
     *
     * @param identifier the identifier that identifies an element for redaction
     * @throws RedactableSignatureException if the given part cannot be processed. E.g. a duplicate in set based
     *                                      algorithm
     */
    protected abstract void engineAddIdentifier(Identifier identifier) throws RedactableSignatureException;

    /**
     * Returns the signature of parts added so far.
     * <p>
     * When this method completes, the state of this object must be reset to the initial state it was in after
     * initialization.
     *
     * @return the signature output of elements added so far
     * @throws RedactableSignatureException if this engine cannot process the given data
     */
    protected abstract SignatureOutput engineSign() throws RedactableSignatureException;

    /**
     * Verifies the given signature output.
     * <p>
     * When this method completes, the state of this object must be reset to the initial state it was in after
     * initialization.
     *
     * @param signature the signature to verify
     * @return true if the signature was verified, false if not
     * @throws RedactableSignatureException if this engine cannot process the given data
     */
    protected abstract boolean engineVerify(SignatureOutput signature) throws RedactableSignatureException;

    /**
     * Redacts the added parts from the given signature.
     * <p>
     * When this method completes, the state of this object must be reset to the initial state it was in after
     * initialization.
     *
     * @param signature the signature to redact
     * @return a redacted version of the given signature
     * @throws RedactableSignatureException if this engine cannot process the given data
     */
    protected abstract SignatureOutput engineRedact(SignatureOutput signature) throws RedactableSignatureException;

    /**
     * Merges the two given signatures.
     * <p>
     * When this method completes, the state of this object must be reset to the initial state it was in after
     * initialization.
     * <p>
     * Implementations may choose not to override this method, since merging is not supported by all redactable
     * signature schemes.
     *
     * @param signature1 a redacted version of a signature output
     * @param signature2 another redacted version of the same original signature
     * @return the merged SignatureOutput of both given signatures
     * @throws RedactableSignatureException if this engine cannot process the given data. E.g. when signatures are from
     *                                      different signers
     */
    protected SignatureOutput engineMerge(SignatureOutput signature1, SignatureOutput signature2)
            throws RedactableSignatureException {

        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support merging");
    }

    /**
     * Updates the given signature with the elements added so far.
     * <p>
     * When this method completes, the state of this object must be reset to the initial state it was in after
     * initialization.
     * <p>
     * Implementations may choose not to override this method, since merging is not supported by all redactable
     * signature schemes.
     *
     * @param original the signature that is going to be updated
     * @return an updated version of the given signature
     * @throws RedactableSignatureException if this engine cannot process the given data. E.g. when signature is
     *                                      generated by a different signer as stated at initialization.
     */
    protected SignatureOutput engineUpdate(SignatureOutput original) throws RedactableSignatureException {
        throw new UnsupportedOperationException("This Redactable Signature Scheme does not support updating");
    }

    /**
     * Initializes this signature engine with the specified parameter set
     *
     * @param parameters the parameters
     * @throws InvalidAlgorithmParameterException if the given parameters ar inappropriate for this engine
     */
    protected abstract void engineSetParameters(AlgorithmParameters parameters)
            throws InvalidAlgorithmParameterException;

    /**
     * Returns the algorithm parameters used by this redactable signature engine or null if this redactable signature
     * engine does not use any parameters.
     *
     * @return the algorithm parameters or null if this engine does not use any parameters.
     */
    protected abstract AlgorithmParameters engineGetParameters();

}
