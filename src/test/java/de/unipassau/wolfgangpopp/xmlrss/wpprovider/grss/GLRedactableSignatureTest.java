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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import org.junit.Test;

import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class GLRedactableSignatureTest extends AbstractRSSTest {

    public GLRedactableSignatureTest() throws NoSuchAlgorithmException {
        super("GLRSSwithRSAandBPA", new WPProvider(), "GLRSSwithRSAandBPA", 512);
    }

    @Override
    @Test
    public void testAddDuplicateParts() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        List<Identifier> identifiers = new LinkedList<>();

        identifiers.add(rss.addPart(TEST_MESSAGE[0]));
        identifiers.add(rss.addPart(TEST_MESSAGE[0]));
        identifiers.add(rss.addPart(TEST_MESSAGE[0]));
        identifiers.add(rss.addPart(TEST_MESSAGE[0], false));
        identifiers.add(rss.addPart(TEST_MESSAGE[0], false));

        SignatureOutput output = rss.sign();

        assertEquals(5, output.size());
        for (Identifier identifier : identifiers) {
            assertTrue(output.contains(identifier));
        }
    }

    @Override
    @Test(expected = RedactableSignatureException.class)
    public void testAddDuplicateIdentifiers() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initRedact(keyPair.getPublic());
        Identifier identifier = new Identifier("test".getBytes(), 1);
        rss.addIdentifier(identifier);
        rss.addIdentifier(identifier);
    }

    @Override
    @Test
    public void testSignSomeRedactable() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        List<Identifier> identifiers = new LinkedList<>();

        identifiers.add(rss.addPart(TEST_MESSAGE[0]));
        identifiers.add(rss.addPart(TEST_MESSAGE[1]));
        identifiers.add(rss.addPart(TEST_MESSAGE[2], false));
        identifiers.add(rss.addPart(TEST_MESSAGE[3], false));

        SignatureOutput output = rss.sign();

        assertEquals(4, output.size());
        for (Identifier identifier : identifiers) {
            assertTrue(output.contains(identifier));
        }
    }

    @Test(expected = RedactableSignatureException.class)
    public void testRedactNonRedactable() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);

        rss.addPart(TEST_MESSAGE[0]);
        rss.addPart(TEST_MESSAGE[1]);
        rss.addPart(TEST_MESSAGE[2], false);
        Identifier identifier = rss.addPart(TEST_MESSAGE[3], false);

        SignatureOutput output = rss.sign();
        rss.initRedact(keyPair.getPublic());
        rss.addIdentifier(identifier);

        rss.redact(output);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNonVerify() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        rss.addPart(TEST_MESSAGE[0]);
        rss.addPart(TEST_MESSAGE[0]);
        rss.addPart(TEST_MESSAGE[0]);

        GLRSSSignatureOutput output = (GLRSSSignatureOutput) rss.sign();
        GLRSSSignatureOutput.GLRSSSignedPart signedPart = output.getParts().get(2);
        Field witnessField = signedPart.getClass().getDeclaredField("witnesses");
        witnessField.setAccessible(true);

        List<ByteArray> witnesses = (List<ByteArray>) witnessField.get(signedPart);
        witnesses.set(0, new ByteArray("h4ck3d".getBytes()));

        rss.initVerify(keyPair.getPublic());
        assertFalse(rss.verify(output));
    }
}