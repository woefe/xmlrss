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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import sun.security.jca.GetInstance;

import javax.xml.crypto.dsig.XMLSignatureException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public abstract class RedactableXMLSignature {

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

    public RedactableXMLSignature getInstance(String algorithm) throws NoSuchAlgorithmException {
        NoSuchAlgorithmException failure = new NoSuchAlgorithmException(algorithm + " RedactableXMLSignature not available");
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

    public RedactableXMLSignature getInstance(String algorithm, String provider) throws NoSuchProviderException, NoSuchAlgorithmException {
        GetInstance.Instance instance = GetInstance.getInstance(TYPE,
                RedactableXMLSignatureSpi.class, algorithm, provider);
        return getInstance(instance, algorithm);
    }

    public static RedactableXMLSignature getInstance(String algorithm, Provider provider) throws NoSuchAlgorithmException {
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

    public final void setRootNode(Node node) throws XMLSignatureException {
        if (state != STATE.UNINITIALIZED) {
            engine.engineSetRootNode(node);
        } else {
            throw new XMLSignatureException("not initialized");
        }
    }

    public final void setDocument(Document document) throws XMLSignatureException {
        setRootNode(document.getDocumentElement());
    }

    public final void addPartSelector(String uri) throws XMLSignatureException {
        if (state != STATE.UNINITIALIZED) {
            engine.engineAddPartSelector(uri);
        } else {
            throw new XMLSignatureException("not initialized");
        }
    }

    public final void sign() throws XMLSignatureException, SignatureException {
        if (state == STATE.SIGN) {
            engine.engineSign();
        }
        throw new XMLSignatureException("not initialized for signing");
    }

    public final boolean verify() throws XMLSignatureException {
        if (state == STATE.VERIFY) {
            return engine.engineVerify();
        }
        throw new XMLSignatureException("not initialized for verification");
    }

    public final void redact() throws XMLSignatureException {
        if (state == STATE.REDACT) {
            engine.engineRedact();
        }
        throw new XMLSignatureException("not initialized for redaction");
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
