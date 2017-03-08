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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.junit.Assert.*;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableXMLSignatureTest {
    private static KeyPair keyPair;

    static {
        Security.insertProviderAt(new WPProvider(), 0);
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("PSRSS");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        generator.initialize(512);
        keyPair = generator.generateKeyPair();
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
        sig.addPartSelector("/");
        sig.sign();


        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        trans.transform(new DOMSource(document), new StreamResult(System.out));

    }

}