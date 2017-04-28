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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import org.junit.Test;
import org.w3c.dom.Document;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public abstract class AbstractXMLRSSTest {

    protected String algorithm;
    protected String providerName;
    protected Provider provider;
    protected KeyPair keyPair;

    public AbstractXMLRSSTest(String algorithm, Provider provider, KeyPair keyPair) {
        Security.insertProviderAt(provider, 1);
        this.algorithm = algorithm;
        this.providerName = provider.getName();
        this.provider = provider;
        this.keyPair = keyPair;
    }

    public AbstractXMLRSSTest(String algorithm, Provider provider, String keyPairGeneratorAlgorithm, int keySize) throws NoSuchAlgorithmException {
        Security.insertProviderAt(provider, 1);
        this.algorithm = algorithm;
        this.providerName = provider.getName();
        this.provider = provider;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
        keyGen.initialize(keySize);
        this.keyPair = keyGen.generateKeyPair();
    }

    @Test
    public void testGetInstance() throws Exception {
        Security.insertProviderAt(provider, 1);
        RedactableXMLSignature rss = RedactableXMLSignature.getInstance(algorithm);
        assertEquals(rss.getAlgorithm(), algorithm);
    }

    @Test
    public void testGetInstanceFromSpecificProviderString() throws Exception {
        Security.insertProviderAt(new WPProvider(), 1);
        RedactableXMLSignature rss = RedactableXMLSignature.getInstance(algorithm, providerName);
        assertEquals(rss.getAlgorithm(), algorithm);
    }

    @Test
    public void testGetInstanceFromSpecificProviderObject() throws Exception {
        Security.insertProviderAt(new WPProvider(), 1);
        RedactableXMLSignature rss = RedactableXMLSignature.getInstance(algorithm, provider);
        assertEquals(rss.getAlgorithm(), algorithm);
    }

    @Test
    public void testSign() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        sig.addSignSelector("#xpointer(id('a3'))", false);
        Document document = sig.sign();
        printDocument(document);
    }

    @Test
    public void testSignAndThenVerify() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        sig.addSignSelector("#xpointer(id('a3'))", false);
        Document document = sig.sign();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
    }

    @Test
    public void testSignThenRedactAndThenVerify() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        sig.addSignSelector("#xpointer(id('a3'))", true);
        Document document = sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addRedactSelector("#xpointer(id('a3'))");
        sig.redact();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
    }

    protected void printDocument(Document document) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        trans.transform(new DOMSource(document), new StreamResult(System.out));
    }
}
