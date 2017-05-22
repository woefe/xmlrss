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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public abstract class AbstractXMLRSSTest {

    protected static KeyPair keyPair;
    private static String keyGenAlgorithm = "";
    protected String algorithm;
    protected String providerName;
    protected Provider provider;

    public AbstractXMLRSSTest(String algorithm, Provider provider, KeyPair keyPair) {
        Security.insertProviderAt(provider, 1);
        this.algorithm = algorithm;
        this.providerName = provider.getName();
        this.provider = provider;
        AbstractXMLRSSTest.keyPair = keyPair;
    }

    public AbstractXMLRSSTest(String algorithm, Provider provider, String keyPairGeneratorAlgorithm, int keySize) throws NoSuchAlgorithmException {
        Security.insertProviderAt(provider, 1);
        this.algorithm = algorithm;
        this.providerName = provider.getName();
        this.provider = provider;

        if (!keyGenAlgorithm.equals(keyPairGeneratorAlgorithm)) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
            keyGen.initialize(keySize);
            keyPair = keyGen.generateKeyPair();
            keyGenAlgorithm = keyPairGeneratorAlgorithm;
        }
    }

    @Test
    public void testGetInstance() throws Exception {
        Security.insertProviderAt(provider, 1);
        RedactableXMLSignature rss = RedactableXMLSignature.getInstance(algorithm);
        assertEquals(algorithm, rss.getAlgorithm());
    }

    @Test
    public void testGetInstanceFromSpecificProviderString() throws Exception {
        Security.insertProviderAt(new WPProvider(), 1);
        RedactableXMLSignature rss = RedactableXMLSignature.getInstance(algorithm, providerName);
        assertEquals(algorithm, rss.getAlgorithm());
    }

    @Test
    public void testGetInstanceFromSpecificProviderObject() throws Exception {
        Security.insertProviderAt(new WPProvider(), 1);
        RedactableXMLSignature rss = RedactableXMLSignature.getInstance(algorithm, provider);
        assertEquals(algorithm, rss.getAlgorithm());
    }

    @Test
    public void testSign() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        sig.addSignSelector("#xpointer(id('a3'))", true);
        Document document = sig.sign();

        printDocument(document);
        validateXSD(document);
    }

    @Test
    public void testSignAndThenVerify() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        sig.addSignSelector("#xpointer(id('a3'))", true);
        Document document = sig.sign();
        printDocument(document);

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
        validateXSD(document);
    }

    @Test
    public void testVerifyFalseModifiedDoc() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        sig.addSignSelector("#xpointer(id('a3'))", true);
        Document document = sig.sign();
        printDocument(document);

        document.getDocumentElement().getFirstChild().getFirstChild().getFirstChild().setNodeValue("broken");

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertFalse(sig.verify());
        validateXSD(document);
    }

    @Test
    public void testVerifyFalseModfiedSig() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        sig.addSignSelector("#xpointer(id('a3'))", true);
        Document document = sig.sign();
        printDocument(document);

        Node proof = document.getElementsByTagName("drs:Proof").item(0);
        proof.removeChild(proof.getFirstChild());

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        try {
            assertFalse(sig.verify());
        } catch (Exception e) {
            assertTrue(true);
        }
        validateXSD(document);
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

        validateXSD(document);

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());

        // ensure that a3 is actually removed
        XPath xPath = XPathFactory.newInstance().newXPath();
        assertNull(xPath.evaluate("//*[@id='a3']", document, XPathConstants.NODE));
        assertNull(xPath.evaluate("//*[@URI=\"#xpointer(id('a3'))\"]", document, XPathConstants.NODE));
    }

    @Test
    public void testRedactOverlapDTD() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('g1'))", true);
        sig.addSignSelector("#xpointer(id('j1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", true);
        Document document = sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addRedactSelector("#xpointer(id('j1'))");
        sig.addRedactSelector("#xpointer(id('g1'))");
        sig.addRedactSelector("#xpointer(id('a1'))");
        sig.redact();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
        //TODO improve checks on result
    }

    @Test
    public void testRedactOverlapSchema() throws Exception {
        Schema schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new File("testdata/test1.xsd"));
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/test1.xml"), schema);
        sig.addSignSelector("#xpointer(id('i1'))", true);
        sig.addSignSelector("#xpointer(id('l1'))", true);
        sig.addSignSelector("#xpointer(id('e1'))", true);
        sig.addSignSelector("#xpointer(id('e2'))", true);
        sig.addSignSelector("#xpointer(id('e3'))", true);
        sig.addSignSelector("#xpointer(id('i3'))", true);
        sig.addSignSelector("#xpointer(id('i2'))", true);
        sig.addSignSelector("#xpointer(id('s1'))", true);
        Document document = sig.sign();

        printDocument(document);

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addRedactSelector("#xpointer(id('i1'))");
        sig.addRedactSelector("#xpointer(id('e2'))");
        sig.addRedactSelector("#xpointer(id('e3'))");
        sig.addRedactSelector("#xpointer(id('e1'))");
        sig.addRedactSelector("#xpointer(id('l1'))");
        sig.addRedactSelector("#xpointer(id('i3'))");
        sig.redact();

        printDocument(document);
        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
        //TODO improve checks on result
    }

    @Test(expected = RedactableXMLSignatureException.class)
    public void testAddPartSelectorDuplicate() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a1'))", true);
    }

    @Test
    public abstract void testAddNonRedactable() throws Exception;

    protected void validateXSD(Document signedDoc) throws SAXException, IOException {
        NodeList nodeList = signedDoc.getElementsByTagNameNS(RedactableXMLSignature.XML_NAMESPACE, "Signature");
        assertEquals(1, nodeList.getLength());

        Node signature = nodeList.item(0);
        NodeList childNodes = signature.getChildNodes();
        int actualNodes = 0;
        for (int i = 0; i < childNodes.getLength(); i++) {
            if (childNodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
                ++actualNodes;
            }
        }
        assertEquals(3, actualNodes);

        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = schemaFactory.newSchema(new File("xmlrss_schema.xsd"));
        Validator validator = schema.newValidator();
        validator.validate(new DOMSource(signature));
    }


    protected void printDocument(Document document) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        trans.transform(new DOMSource(document), new StreamResult(System.out));
    }
}
