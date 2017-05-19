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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AbstractRSSTest;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class GSRedactableSignatureTest extends AbstractRSSTest {

    public GSRedactableSignatureTest() throws NoSuchAlgorithmException {
        super("GSRSSwithRSAandBPA", new WPProvider(), "GSRSSwithRSAandBPA", 512);
    }

    @Override
    @Test
    public void testSignSomeRedactable() throws Exception {
        RedactableSignature sig = RedactableSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.addPart(TEST_MESSAGE[0], true);
        sig.addPart(TEST_MESSAGE[1], true);
        sig.addPart(TEST_MESSAGE[2], false);
        sig.addPart(TEST_MESSAGE[3], false);
        SignatureOutput output = sig.sign();

        sig.initVerify(keyPair.getPublic());
        assertTrue(sig.verify(output));
        assertTrue(output.containsAll(Arrays.copyOfRange(TEST_MESSAGE, 0, 4)));
        assertEquals(4, output.size());
    }

    @Test(expected = RedactableSignatureException.class)
    public void testRedactNonRedactable() throws Exception {
        RedactableSignature sig = RedactableSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.addPart(TEST_MESSAGE[0], true);
        sig.addPart(TEST_MESSAGE[1], true);
        sig.addPart(TEST_MESSAGE[2], false);
        Identifier identifier = sig.addPart(TEST_MESSAGE[3], false);
        SignatureOutput output = sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.addIdentifier(identifier);
        SignatureOutput redacted = sig.redact(output);
    }

    @Override
    @Test(expected = RedactableSignatureException.class)
    public void testAddDuplicateParts() throws Exception {
        RedactableSignature sig = RedactableSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        sig.addPart("test".getBytes());
        sig.addPart("test".getBytes());
    }

    @Override
    @Test(expected = RedactableSignatureException.class)
    public void testAddDuplicateIdentifiers() throws Exception {
        RedactableSignature sig = RedactableSignature.getInstance(algorithm);
        sig.initSign(keyPair);
        Identifier identifier = new Identifier("test".getBytes());
        sig.addIdentifier(identifier);
        sig.addIdentifier(identifier);
    }

}