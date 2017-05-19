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
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableXMLSignatureTest extends AbstractXMLRSSTest {

    public PSRedactableXMLSignatureTest() {
        super("XMLPSRSSwithPSA", new WPProvider(), new KeyPair(
                new PSRSSPublicKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412906735607605108373982421012500888307062421310001762155422489671132976679912849")),
                new PSRSSPrivateKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412734960638035580933850038621738468566657503090109097536944629352405060890801636"))
        ));
    }

    @Override
    @Test(expected = RedactableXMLSignatureException.class)
    public void testAddNonRedactable() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a3'))", false);
    }

    @Test
    public void engineVerifyFail() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new File("testdata/vehicles.sig.xml"));

        NodeList nodeList = document.getElementsByTagNameNS(RedactableXMLSignature.XML_NAMESPACE, "Signature");
        assertEquals(1, nodeList.getLength());

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertFalse(sig.verify());
        validateXSD(document);
    }

}