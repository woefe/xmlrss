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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import sun.security.jca.GetInstance;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.List;

/**
 * The <code>RedactableXMLSignature</code> handles signing, verification, and redaction of XML documents using a
 * redactable signature scheme. Redactable signatures allow to remove parts from a signed XML document without
 * invalidating the attached signature.
 * <p>
 * A <code>RedactableXMLSignature</code> object can be used to sign, verify, redact XML documents. Note that redactable
 * signature schemes exist which do not support merging or updating operations. A <code>RedactableXMLSignature</code>
 * object is used in different phases, depending on the operation.
 * <p>
 * Sign:
 * <ol>
 * <li>{@link #initSign(KeyPair)}</li>
 * <li>{@link #setDocument(Document)}</li>
 * <li>{@link #addSignSelector(String, boolean)}</li>
 * <li>{@link #sign()}</li>
 * </ol>
 * <p>
 * Verify:
 * <ol>
 * <li>{@link #initVerify(PublicKey)}</li>
 * <li>{@link #setDocument(Document)}</li>
 * <li>{@link #verify()}</li>
 * </ol>
 * <p>
 * Redact:
 * <ol>
 * <li>{@link #initRedact(PublicKey)}</li>
 * <li>{@link #setDocument(Document)}</li>
 * <li>{@link #addRedactSelector(String)}</li>
 * <li>{@link #redact()}</li>
 * </ol>
 *
 * @author Wolfgang Popp
 */
public abstract class RedactableXMLSignature {

    public static final String XML_NAMESPACE = "https://sec.uni-passau.de/2017/03/xmlrss";
    private static final String TYPE = "RedactableXMLSignature";
    private Provider provider;
    private String algorithm;
    private STATE state;
    private RedactableXMLSignatureSpi engine;

    private enum STATE {
        UNINITIALIZED, SIGN, REDACT, VERIFY
    }

    /**
     * Constructs a new RedactableXMLSignature object with the given engine and algorithm name.
     *
     * @param engine    the underlying engine of this RedactableXMLSignature
     * @param algorithm the algorithm name
     */
    RedactableXMLSignature(RedactableXMLSignatureSpi engine, String algorithm) {
        this.algorithm = algorithm;
        this.engine = engine;
        this.state = STATE.UNINITIALIZED;
    }

    /**
     * Returns a RedactableXMLSignature object that implements the specified redactable signature algorithm.
     * <p>
     * This method traverses the list of registered security Providers, starting with the most preferred Provider. A new
     * RedactableXMLSignature object encapsulating the RedactableXMLSignatureSpi implementation from the first Provider
     * that supports the specified algorithm is returned.
     * <p>
     * Note that the list of registered providers may be retrieved via the <code>Security.getProviders()</code> method.
     *
     * @param algorithm the name of the requested algorithm
     * @return a new RedactableXMLSignature object.
     * @throws NoSuchAlgorithmException if no Provider supports a RedactableXMLSignature implementation for the
     *                                  specified algorithm.
     */
    public static RedactableXMLSignature getInstance(String algorithm) throws NoSuchAlgorithmException {
        NoSuchAlgorithmException failure = new NoSuchAlgorithmException(algorithm
                + " RedactableXMLSignature not available");
        List<Provider.Service> services = GetInstance.getServices(TYPE, algorithm);

        for (Provider.Service service : services) {
            try {
                GetInstance.Instance instance = GetInstance.getInstance(service, RedactableXMLSignatureSpi.class);
                return getInstance(instance, algorithm);
            } catch (NoSuchAlgorithmException e) {
                failure = e;
            }
        }
        throw failure;
    }

    /**
     * Returns a RedactableXMLSignature object that implements the specified redactable signature algorithm.
     * <p>
     * A new RedactableXMLSignature object encapsulating the RedactableXMLSignatureSpi implementation from the specified
     * provider is returned. The specified provider must be registered in the security provider list.
     * <p>
     * Note that the list of registered providers may be retrieved via the <code>Security.getProviders()</code> method.
     *
     * @param algorithm the name of the requested algorithm
     * @param provider  the name of the provider
     * @return a new RedactableXMLSignature object.
     * @throws NoSuchProviderException  if the specified provider is not registered in the security provider list.
     * @throws NoSuchAlgorithmException if a RedactableXMLSignatureSpi implementation for the specified algorithm is not
     *                                  available from the specified provider.
     */
    public static RedactableXMLSignature getInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance(TYPE,
                RedactableXMLSignatureSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    /**
     * Returns a RedactableXMLSignature object that implements the specified redactable signature algorithm.
     * <p>
     * A new RedactableXMLSignature object encapsulating the RedactableXMLSignatureSpi implementation from the specified
     * provider object is returned. Note that the specified provider object does not have to be registered in the
     * security provider list.
     *
     * @param algorithm the name of the requested algorithm
     * @param provider  the provider
     * @return a new RedactableSignature object.
     * @throws NoSuchAlgorithmException if a RedactableXMLSignatureSpi implementation for the specified algorithm is not
     *                                  available from the specified provider.
     */
    public static RedactableXMLSignature getInstance(String algorithm, Provider provider)
            throws NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance(TYPE,
                RedactableXMLSignatureSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    private static RedactableXMLSignature getInstance(GetInstance.Instance instance, String algorithm) {
        RedactableXMLSignature sig;
        if (instance.impl instanceof RedactableXMLSignature) {
            sig = (RedactableXMLSignature) instance.impl;
            sig.algorithm = algorithm;
        } else {
            RedactableXMLSignatureSpi spi = (RedactableXMLSignatureSpi) instance.impl;
            sig = new Delegate(spi, algorithm);
        }
        sig.provider = instance.provider;
        return sig;
    }

    /**
     * Returns the {@link Provider} of this RedactableXMLSignature object
     *
     * @return the provider of this RedactableXMLSignature object
     */
    public final Provider getProvider() {
        return provider;
    }

    /**
     * Returns the name of the algorithm for this RedactableXMLSignature object.
     *
     * @return the name of the algorithm for this RedactableXMLSignature object
     */
    public final String getAlgorithm() {
        return algorithm;
    }

    /**
     * Initializes this object for signing.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableXMLSignature.
     *
     * @param keyPair the keypair of the identity whose signature is going to be generated.
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing the underlying
     *                             RedactableSignature object.
     */
    public final void initSign(KeyPair keyPair) throws InvalidKeyException {
        state = STATE.SIGN;
        engine.engineInitSign(keyPair);
    }

    /**
     * Initializes this object for signing.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableXMLSignature.
     *
     * @param keyPair the keypair of the identity whose signature is going to be generated.
     * @param random  the source of randomness for this signature
     * @throws InvalidKeyException if the given keypair is inappropriate for initializing the underlying
     *                             RedactableSignature object.
     */
    public final void initSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        state = STATE.SIGN;
        engine.engineInitSign(keyPair, random);
    }

    /**
     * Initializes this object for verification.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableXMLSignature.
     *
     * @param publicKey the public key of the identity whose signature is going to be verified.
     * @throws InvalidKeyException if the given public key is inappropriate for initializing the underlying
     *                             RedactableSignature object.
     */
    public final void initVerify(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.VERIFY;
        engine.engineInitVerify(publicKey);

    }

    /**
     * Initializes this object for redaction.
     * <p>
     * Note that the initialization discards all previous state, i.e. initialization is equivalent to creating a new
     * instance of that RedactableXMLSignature.
     *
     * @param publicKey the public key of the identity whose signature is going to be redacted.
     * @throws InvalidKeyException if the given public key is inappropriate for initializing the underlying
     *                             RedactableSignature object.
     */
    public final void initRedact(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.REDACT;
        engine.engineInitRedact(publicKey);
    }

    /**
     * Sets the root node of the used document.
     * <p>
     * Alternatively, one of the <code>setDocument()</code> methods can be used.
     *
     * @param node the root node
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature object is not properly initialized
     */
    public final void setRootNode(Node node) throws RedactableXMLSignatureException {
        if (state != STATE.UNINITIALIZED) {
            engine.engineSetRootNode(node);
        } else {
            throw new RedactableXMLSignatureException("not initialized");
        }
    }

    /**
     * Set the document used for signing/verification/redaction.
     *
     * @param document the document
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature object is not properly initialized
     */
    public final void setDocument(Document document) throws RedactableXMLSignatureException {
        setRootNode(document.getDocumentElement());
    }

    /**
     * Load the document used for signing/verification/redaction from the given input stream.
     * <p>
     * The document should reference a Document Type Definition (DTD).
     *
     * @param inputStream the input stream
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature object is not properly initialized
     */
    public final void setDocument(InputStream inputStream) throws RedactableXMLSignatureException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setValidating(true);
        documentBuilderFactory.setIgnoringElementContentWhitespace(true);

        try {
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            setDocument(documentBuilder.parse(inputStream));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    /**
     * Loads the document used for signing/verification/redaction from the given input stream.
     * <p>
     * The document is checked against the given schema and the default error handler is used (as specified in
     * {@link DocumentBuilder#setErrorHandler(ErrorHandler)})
     *
     * @param inputStream the input stream
     * @param schema      the schema of the loaded XML document
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature object is not properly initialized
     */
    public final void setDocument(InputStream inputStream, Schema schema) throws RedactableXMLSignatureException {
        setDocument(inputStream, schema, null);
    }

    /**
     * Loads the document used for signing/verification/redaction from the given input stream.
     * <p>
     * The document is checked against the given schema and the given error handler is used.
     *
     * @param inputStream the input stream
     * @param schema      the schema of the loaded XML document
     * @param handler     the errorhandler
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature object is not properly initialized
     */
    public final void setDocument(InputStream inputStream, Schema schema, ErrorHandler handler)
            throws RedactableXMLSignatureException {

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setSchema(schema);
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setIgnoringElementContentWhitespace(true);

        try {
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            documentBuilder.setErrorHandler(handler);
            setDocument(documentBuilder.parse(inputStream));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    /**
     * Selects the given uri from the document for signing.
     *
     * @param uri          the URI of the selected element
     * @param isRedactable indicates whether the selected element is redactable
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature is not initialized for signing or if the
     *                                         given URI cannot be added
     */
    public final void addSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        if (state == STATE.SIGN) {
            engine.engineAddSignSelector(uri, isRedactable);
        } else {
            throw new RedactableXMLSignatureException("not for signing");
        }
    }

    /**
     * Selects the given uri from the document for redaction.
     * <p>
     * Every message part added with this method can later be redacted if the given boolean flag is set to true.
     *
     * @param uri the URI of the selected element
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature is not initialized for redaction or if the
     *                                         given URI cannot be added (e.g. when it was not previously signed)
     */
    public final void addRedactSelector(String uri) throws RedactableXMLSignatureException {
        if (state == STATE.REDACT) {
            engine.engineAddRedactSelector(uri);
        } else {
            throw new RedactableXMLSignatureException("not for redaction");
        }
    }

    /**
     * Signs the selected elements that were added via {@link #addSignSelector(String, boolean)}.
     * <p>
     * This method creates the redactable signature XML element and adds it as the last child of the root node of the
     * previously loaded document.
     * <p>
     * A call of this method resets this object to the initial state, which is the state it was in after a call of
     * {@link #initSign(KeyPair)}. That is, the object is reset and available to generate another signature from the
     * same signer.
     *
     * @return the previously loaded document that has now a new signature element embedded
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature is not initialized for signing or the
     *                                         underlying algorithms cannot process the requested elements
     */
    public final Document sign() throws RedactableXMLSignatureException {
        if (state == STATE.SIGN) {
            return engine.engineSign();
        } else {
            throw new RedactableXMLSignatureException("not initialized for signing");
        }
    }

    /**
     * Verifies the signature of the previously loaded XML document.
     * <p>
     * Note that the given document should have the <code>Signature</code> element.
     * <p>
     * A call of this method resets this object to the initial state, which is the state it was in after a call of
     * {@link #initVerify(PublicKey)}. That is, the object is reset and available to verify another signature from the
     * same identity whose public key was set via {@link #initVerify(PublicKey)}.
     *
     * @return true, if the signature verified, false otherwise
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature is not initialized for verification or the
     *                                         loaded document does not have a <code>Signature</code> element
     */
    public final boolean verify() throws RedactableXMLSignatureException {
        if (state == STATE.VERIFY) {
            return engine.engineVerify();
        }
        throw new RedactableXMLSignatureException("not initialized for verification");
    }

    /**
     * Redacts the selected elements that were added via a {@link #addRedactSelector(String)} method.
     * <p>
     * This method modifies the previously loaded document in-place.
     * <p>
     * A call of this method resets this object to the initial state, which is the state it was in after a call of
     * {@link #initRedact(PublicKey)}. That is, the object is reset and available to verify another signature from the
     * same identity whose public key was set via {@link #initRedact(PublicKey)}.
     *
     * @return the modified/redacted document
     * @throws RedactableXMLSignatureException if this RedactableXMLSignature is not initialized for redaction or the
     *                                         loaded document does not have a <code>Signature</code> element or the
     *                                         redactions lead to XML validity errors
     */
    public final Document redact() throws RedactableXMLSignatureException {
        if (state == STATE.REDACT) {
            return engine.engineRedact();
        }
        throw new RedactableXMLSignatureException("not initialized for redaction");
    }

    //TODO algorithm parameters

    @Override
    public String toString() {
        return "RedactableXMLSignature (Algorithm: " + getAlgorithm() + ", Initialization state: " + state + ")";
    }

    static class Delegate extends RedactableXMLSignature {
        Delegate(RedactableXMLSignatureSpi engine, String algorithm) {
            super(engine, algorithm);
        }
    }
}
