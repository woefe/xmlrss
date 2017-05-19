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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.junit.Test;
import org.w3c.dom.Document;

import java.io.FileInputStream;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class GSRedactableXMLSignatureTest extends AbstractXMLRSSTest {

    public GSRedactableXMLSignatureTest() throws NoSuchAlgorithmException {
        super("GSRSSwithRSAandBPA", new WPProvider(), "GSRSSwithRSAandBPA", 512);
    }

    @Override
    @Test
    public void testAddNonRedactable() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", false);
        Document document = sig.sign();
        printDocument(document);

        sig.initVerify(keyPair.getPublic());
        sig.setDocument(document);
        assertTrue(sig.verify());
        validateXSD(document);
    }

    @Test(expected = RedactableXMLSignatureException.class)
    public void testRedactNonRedactable() throws Exception {
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.setDocument(new FileInputStream("testdata/vehicles.xml"));
        sig.addSignSelector("#xpointer(id('a1'))", true);
        sig.addSignSelector("#xpointer(id('a2'))", false);
        Document document = sig.sign();
        printDocument(document);

        sig.initRedact(keyPair.getPublic());
        sig.setDocument(document);
        sig.addRedactSelector("#xpointer(id('a2'))");
        sig.redact();
    }
}