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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AbstractXMLRSSTest;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableXMLSignatureTest extends AbstractXMLRSSTest {
    private static final KeyPair keyPair;

    static {
        Security.insertProviderAt(new WPProvider(), 0);
        PSRSSPublicKey publicKey256 = new PSRSSPublicKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412906735607605108373982421012500888307062421310001762155422489671132976679912849"));
        PSRSSPrivateKey privateKey256 = new PSRSSPrivateKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412734960638035580933850038621738468566657503090109097536944629352405060890801636"));
        keyPair = new KeyPair(publicKey256, privateKey256);
    }

    @Test
    public void engineSign() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new FileInputStream("testdata/vehicles.xml"));

        sig.initSign(keyPair);
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        sig.addPartSelector("#xpointer(id('a3'))");
        sig.sign();

        validateXSD(document);

        //printDocument(document)
    }

    private void validateXSD(Document signedDoc) throws SAXException, IOException {
        NodeList nodeList = signedDoc.getElementsByTagNameNS(PSRedactableXMLSignature.XML_NAMESPACE, "Signature");
        assertEquals(nodeList.getLength(), 1);

        Node signature = nodeList.item(0);
        assertEquals(signature.getChildNodes().getLength(), 2);

        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = schemaFactory.newSchema(new File("psrss_schema.xsd"));
        Validator validator = schema.newValidator();
        validator.validate(new DOMSource(signature));
    }

    @Test(expected = RedactableXMLSignatureException.class)
    public void engineAddPartSelectorDuplicate() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addPartSelector("#xpointer(id('a3'))");
        sig.addPartSelector("#xpointer(id('a3'))"); // throws RedactableXMLSignatureException
    }

    @Test
    public void engineVerify() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        sig.addPartSelector("#xpointer(id('a3'))");
        Document signedDocument = sig.sign();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(signedDocument);
        assertTrue(sig.verify());
        validateXSD(signedDocument);
    }

    @Test
    public void engineVerifyFail() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File("testdata/vehicles.sig.xml"));

        NodeList nodeList = document.getElementsByTagName("Signature");
        assertEquals(nodeList.getLength(), 1);

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertFalse(sig.verify());
        validateXSD(document);
    }

    @Test
    public void engineRedact() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        sig.addPartSelector("#xpointer(id('a3'))");
        Document document = sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('a3'))");
        sig.redact();

        validateXSD(document);

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());

        // ensure that a3 is actually removed
        XPath xPath = XPathFactory.newInstance().newXPath();
        assertNull(xPath.evaluate("//*[@id='a3']", document, XPathConstants.NODE));
        assertNull(xPath.evaluate("//*[@URI=\"#xpointer(id('a3'))\"]", document, XPathConstants.NODE));

        //printDocument(document)
    }

    @Test
    public void testRedactOverlapDTD() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('g1'))");
        sig.addPartSelector("#xpointer(id('j1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        Document document = sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('j1'))");
        sig.addPartSelector("#xpointer(id('g1'))");
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.redact();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
    }

    @Test
    public void testRedactOverlapSchema() throws Exception {
        Schema schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new File("testdata/test1.xsd"));
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/test1.xml"), schema);
        sig.addPartSelector("#xpointer(id('i1'))");
        sig.addPartSelector("#xpointer(id('l1'))");
        sig.addPartSelector("#xpointer(id('e1'))");
        sig.addPartSelector("#xpointer(id('e2'))");
        sig.addPartSelector("#xpointer(id('e3'))");
        sig.addPartSelector("#xpointer(id('i3'))");
        sig.addPartSelector("#xpointer(id('i2'))");
        sig.addPartSelector("#xpointer(id('s1'))");
        Document document = sig.sign();

        printDocument(document);

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('i1'))");
        sig.addPartSelector("#xpointer(id('e2'))");
        sig.addPartSelector("#xpointer(id('e3'))");
        sig.addPartSelector("#xpointer(id('e1'))");
        sig.addPartSelector("#xpointer(id('l1'))");
        sig.addPartSelector("#xpointer(id('i3'))");
        sig.redact();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
    }
}