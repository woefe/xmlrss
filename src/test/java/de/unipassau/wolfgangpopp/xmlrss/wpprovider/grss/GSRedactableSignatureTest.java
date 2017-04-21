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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class GSRedactableSignatureTest {

    private KeyPair keyPair;
    private RedactableSignature sig;

    private static final byte[][] message = {
            "Test1".getBytes(),
            "Test2".getBytes(),
            "Test3".getBytes(),
            "Test4".getBytes(),
    };

    static {
        Security.insertProviderAt(new WPProvider(), 1);
    }

    @Before
    public void init() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("GSRSSwithRSAandBPA");
        keyGen.initialize(512);
        keyPair = keyGen.generateKeyPair();
        sig = RedactableSignature.getInstance("GSRSSwithRSAandBPA", new WPProvider());
    }

    @Test
    public void testSignAndVerify() throws Exception {
        sig.initSign(keyPair);
        sig.addPart(message[0], true);
        sig.addPart(message[1], true);
        sig.addPart(message[2], false);
        sig.addPart(message[3], false);

        SignatureOutput output = sig.sign();

        sig.initVerify(keyPair.getPublic());
        assertTrue(sig.verify(output));
    }

    @Test(expected = RedactableSignatureException.class)
    public void testAddDuplicates() throws Exception {
        sig.initSign(keyPair);
        sig.addPart("test".getBytes());
        sig.addPart("test".getBytes());
    }

    @Test
    public void testSignRedactandVerify() throws Exception {
        sig.initSign(keyPair);
        sig.addPart(message[0], true);
        Identifier identifier = sig.addPart(message[1], true);
        sig.addPart(message[2], false);
        sig.addPart(message[3], false);
        SignatureOutput output = sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.addIdentifier(identifier);
        SignatureOutput redacted = sig.redact(output);

        assertTrue(redacted.containsAll(message[0], message[2], message[3]));
        assertEquals(redacted.size(), 3);

        sig.initVerify(keyPair.getPublic());
        assertTrue(sig.verify(redacted));
    }

    @Test(expected = RedactableSignatureException.class)
    public void testRedactNonRedactable() throws Exception {
        sig.initSign(keyPair);
        sig.addPart(message[0], true);
        sig.addPart(message[1], true);
        sig.addPart(message[2], false);
        sig.addPart(message[3], false);
        SignatureOutput output = sig.sign();


        sig.initRedact(keyPair.getPublic());
        sig.addPart(message[3]);
        SignatureOutput redacted = sig.redact(output);
    }

}