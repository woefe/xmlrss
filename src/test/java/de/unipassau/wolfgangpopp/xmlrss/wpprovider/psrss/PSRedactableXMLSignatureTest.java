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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;

import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableXMLSignatureTest {
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
        Document document = documentBuilder.parse(new File("vehicles.xml"));

        sig.initSign(keyPair);
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        sig.addPartSelector("#xpointer(id('a3'))");
        sig.sign();

        NodeList nodeList = document.getElementsByTagNameNS(RedactableXMLSignature.XML_NAMESPACE, "Signature");
        assertEquals(nodeList.getLength(), 1);
        assertEquals(nodeList.item(0).getChildNodes().getLength(), 2);

//        TransformerFactory tf = TransformerFactory.newInstance();
//        Transformer trans = tf.newTransformer();
//        trans.setOutputProperty(OutputKeys.DOCTYPE_SYSTEM, "vehicles.dtd");
////        trans.setOutputProperty(OutputKeys.INDENT, "yes");
////        trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
//        trans.transform(new DOMSource(document), new StreamResult(new FileOutputStream("vehicles.sig.xml")));
    }

    @Test
    public void engineVerify() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File("vehicles.xml"));

        sig.initSign(keyPair);
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        sig.addPartSelector("#xpointer(id('a3'))");
        sig.sign();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
    }

    @Test
    public void engineVerifyFail() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File("vehicles.sig.xml"));

        NodeList nodeList = document.getElementsByTagName("Signature");
        assertEquals(nodeList.getLength(), 1);

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertFalse(sig.verify());
    }

    @Test
    public void engineRedact() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance("XMLPSRSSwithPSA");

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File("vehicles.xml"));

        sig.initSign(keyPair);
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        sig.addPartSelector("#xpointer(id('a3'))");
        sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addPartSelector("#xpointer(id('a3'))");
        sig.redact();

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        trans.transform(new DOMSource(document), new StreamResult(System.out));
    }
}