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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.xml;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AbstractXMLRSSTest;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * @author Wolfgang Popp
 */
public class GSRedactableXMLSignatureTest extends AbstractXMLRSSTest {

    private KeyPair keyPair;
    private String algorithm;

    static {
        Security.insertProviderAt(new WPProvider(), 2);
    }

    @Before
    public void setUp() throws Exception {
        algorithm = "GSRSSwithRSAandBPA";
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        keyGen.initialize(512);
        keyPair = keyGen.generateKeyPair();
    }

    @Test
    public void testSign() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addPartSelector("#xpointer(id('a1'))");
        sig.addPartSelector("#xpointer(id('a2'))");
        sig.addPartSelector("#xpointer(id('a3'))");
        Document document = sig.sign();
        printDocument(document);
    }

}