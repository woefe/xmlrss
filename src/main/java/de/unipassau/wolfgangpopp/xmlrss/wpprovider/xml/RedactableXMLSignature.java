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

    RedactableXMLSignature(RedactableXMLSignatureSpi engine, String algorithm) {
        this.algorithm = algorithm;
        this.engine = engine;
        this.state = STATE.UNINITIALIZED;
    }

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

    public static RedactableXMLSignature getInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        GetInstance.Instance instance = GetInstance.getInstance(TYPE,
                RedactableXMLSignatureSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

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

    public final Provider getProvider() {
        return provider;
    }

    public final String getAlgorithm() {
        return algorithm;
    }

    public final void initSign(KeyPair keyPair) throws InvalidKeyException {
        state = STATE.SIGN;
        engine.engineInitSign(keyPair);
    }

    public final void initSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        state = STATE.SIGN;
        engine.engineInitSign(keyPair, random);
    }

    public final void initVerify(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.VERIFY;
        engine.engineInitVerify(publicKey);

    }

    public final void initRedact(PublicKey publicKey) throws InvalidKeyException {
        state = STATE.REDACT;
        engine.engineInitRedact(publicKey);
    }

    public final void setRootNode(Node node) throws RedactableXMLSignatureException {
        if (state != STATE.UNINITIALIZED) {
            engine.engineSetRootNode(node);
        } else {
            throw new RedactableXMLSignatureException("not initialized");
        }
    }

    public final void setDocument(Document document) throws RedactableXMLSignatureException {
        setRootNode(document.getDocumentElement());
    }

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

    public final void setDocument(InputStream inputStream, Schema schema) throws RedactableXMLSignatureException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setSchema(schema);
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setIgnoringElementContentWhitespace(true);

        try {
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            setDocument(documentBuilder.parse(inputStream));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    public final void addSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        if (state == STATE.SIGN) {
            engine.engineAddSignSelector(uri, isRedactable);
        } else {
            throw new RedactableXMLSignatureException("not for signing");
        }
    }

    public final void addRedactSelector(String uri) throws RedactableXMLSignatureException {
        if (state == STATE.REDACT) {
            engine.engineAddRedactSelector(uri);
        } else {
            throw new RedactableXMLSignatureException("not for redaction");
        }
    }

    public final Document sign() throws RedactableXMLSignatureException {
        if (state == STATE.SIGN) {
            return engine.engineSign();
        } else {
            throw new RedactableXMLSignatureException("not initialized for signing");
        }
    }

    public final boolean verify() throws RedactableXMLSignatureException {
        if (state == STATE.VERIFY) {
            return engine.engineVerify();
        }
        throw new RedactableXMLSignatureException("not initialized for verification");
    }

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
