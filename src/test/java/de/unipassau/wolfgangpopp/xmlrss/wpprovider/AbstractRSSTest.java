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

import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public abstract class AbstractRSSTest {

    protected static byte[][] TEST_MESSAGE = {
            "This is a test".getBytes(),
            "This is still a test".getBytes(),
            "Moar testing".getBytes(),
            "oi23jröoqi32joqjslkjflaskjdflk".getBytes(),
            "What else could I write here?".getBytes(),
            "21 is only half the truth".getBytes(),
            ("Doloremque velit at quia ad corporis nemo. Quod eveniet minima quasi minima dolorem consectetur." +
                    " Debitis voluptas sunt dolores. Vel voluptatem perspiciatis beatae vel sequi et ullam. Ullam" +
                    " explicabo est sint vel omnis laborum aperiam.").getBytes(),
    };

    protected static KeyPair keyPair = null;
    private static String keyGenAlgorithm = "";
    protected String algorithm;
    protected String providerName;
    protected Provider provider;

    public AbstractRSSTest(String algorithm, Provider provider, KeyPair keyPair) {
        Security.insertProviderAt(provider, 1);
        this.algorithm = algorithm;
        this.providerName = provider.getName();
        this.provider = provider;
        AbstractRSSTest.keyPair = keyPair;
    }

    public AbstractRSSTest(String algorithm, Provider provider, String keyPairGeneratorAlgorithm, int keySize) throws NoSuchAlgorithmException {
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
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        assertEquals(rss.getAlgorithm(), algorithm);
    }

    @Test
    public void testGetInstanceFromSpecificProviderString() throws Exception {
        Security.insertProviderAt(new WPProvider(), 1);
        RedactableSignature rss = RedactableSignature.getInstance(algorithm, providerName);
        assertEquals(rss.getAlgorithm(), algorithm);
    }

    @Test
    public void testGetInstanceFromSpecificProviderObject() throws Exception {
        Security.insertProviderAt(new WPProvider(), 1);
        RedactableSignature rss = RedactableSignature.getInstance(algorithm, provider);
        assertEquals(rss.getAlgorithm(), algorithm);
    }

    @Test
    public void testSignAllRedactable() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        rss.addPart(TEST_MESSAGE[0]);
        rss.addPart(TEST_MESSAGE[1]);
        rss.addPart(TEST_MESSAGE[2]);
        rss.addPart(TEST_MESSAGE[3]);
        rss.addPart(TEST_MESSAGE[4]);
        rss.addPart(TEST_MESSAGE[5], true);
        rss.addPart(TEST_MESSAGE[6], true);

        SignatureOutput output = rss.sign();
        assertTrue(output.containsAll(TEST_MESSAGE));
        assertEquals(output.size(), TEST_MESSAGE.length);
    }

    @Test
    public void testSignAndThenVerifyOnNewObject() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        rss.addPart(TEST_MESSAGE[0]);
        rss.addPart(TEST_MESSAGE[1]);

        SignatureOutput output = rss.sign();

        rss = RedactableSignature.getInstance(algorithm);
        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(output));
    }

    @Test
    public void testSignThenRedactAndThenVerifyOnNewObject() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        Identifier identifier = rss.addPart(TEST_MESSAGE[0]);
        rss.addPart(TEST_MESSAGE[1]);
        rss.addPart(TEST_MESSAGE[2]);
        SignatureOutput original = rss.sign();

        rss = RedactableSignature.getInstance(algorithm);
        rss.initRedact(keyPair.getPublic());
        rss.addIdentifier(identifier);
        rss.addIdentifier(new Identifier(TEST_MESSAGE[1], 1));
        SignatureOutput redacted = rss.redact(original);

        rss = RedactableSignature.getInstance(algorithm);
        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(original));
        assertTrue(rss.verify(redacted));
        assertFalse(redacted.contains(TEST_MESSAGE[0]));
        assertFalse(redacted.contains(TEST_MESSAGE[1]));
    }

    @Test
    public void testSignAndThenVerifyOnSameObject() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);

        rss.initSign(keyPair);
        rss.addPart(TEST_MESSAGE[0]);
        rss.addPart(TEST_MESSAGE[1]);
        SignatureOutput output = rss.sign();

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(output));
    }

    @Test
    public void testSignThenRedactAndThenVerifyOnSameOject() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        rss.addPart(TEST_MESSAGE[2]);
        rss.addPart(TEST_MESSAGE[3]);
        rss.addPart(TEST_MESSAGE[6]);
        Identifier identifier4 = rss.addPart(TEST_MESSAGE[4]);
        Identifier identifier5 = rss.addPart(TEST_MESSAGE[5]);
        SignatureOutput original = rss.sign();

        rss.initRedact(keyPair.getPublic());
        rss.addIdentifier(identifier5);
        rss.addIdentifier(identifier4);
        rss.addIdentifier(new Identifier(TEST_MESSAGE[6], 2));
        SignatureOutput redacted = rss.redact(original);

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(original));
        assertTrue(rss.verify(redacted));

        assertFalse(redacted.contains(TEST_MESSAGE[4]));
        assertFalse(redacted.contains(TEST_MESSAGE[5]));
        assertFalse(redacted.contains(TEST_MESSAGE[6]));
        assertTrue(redacted.containsAll(TEST_MESSAGE[2], TEST_MESSAGE[3]));
    }

    @Test
    public void testSignAndThenSign() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        rss.addPart(TEST_MESSAGE[2]);
        rss.addPart(TEST_MESSAGE[3]);
        rss.addPart(TEST_MESSAGE[6]);
        SignatureOutput first = rss.sign();

        rss.addPart(TEST_MESSAGE[2]);
        rss.addPart(TEST_MESSAGE[4]);
        rss.addPart(TEST_MESSAGE[5]);
        SignatureOutput second = rss.sign();

        assertTrue(first.containsAll(TEST_MESSAGE[2], TEST_MESSAGE[3], TEST_MESSAGE[6]));
        assertEquals(first.size(), 3);
        assertTrue(second.containsAll(TEST_MESSAGE[2], TEST_MESSAGE[4], TEST_MESSAGE[5]));
        assertEquals(second.size(), 3);
        assertFalse(second.contains(TEST_MESSAGE[3]));
    }

    @Test
    public void testRedactAndThenRedact() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance(algorithm);
        rss.initSign(keyPair);
        Identifier identifier0 = rss.addPart(TEST_MESSAGE[0]);
        Identifier identifier1 = rss.addPart(TEST_MESSAGE[1]);
        Identifier identifier2 = rss.addPart(TEST_MESSAGE[2]);
        Identifier identifier3 = rss.addPart(TEST_MESSAGE[3]);
        Identifier identifier4 = rss.addPart(TEST_MESSAGE[4]);
        Identifier identifier5 = rss.addPart(TEST_MESSAGE[5]);
        SignatureOutput original = rss.sign();

        rss.initRedact(keyPair.getPublic());
        rss.addIdentifier(identifier0);
        rss.addIdentifier(identifier2);
        rss.addIdentifier(identifier4);
        SignatureOutput redacted1 = rss.redact(original);

        rss.addIdentifier(identifier1);
        rss.addIdentifier(identifier3);
        rss.addIdentifier(identifier5);
        SignatureOutput redacted2 = rss.redact(original);

        assertTrue(redacted1.containsAll(TEST_MESSAGE[1], TEST_MESSAGE[3], TEST_MESSAGE[5]));
        assertTrue(redacted2.containsAll(TEST_MESSAGE[0], TEST_MESSAGE[2], TEST_MESSAGE[4]));
        assertEquals(redacted1.size(), 3);
        assertEquals(redacted2.size(), 3);
        assertFalse(redacted1.contains(TEST_MESSAGE[0]));
        assertFalse(redacted2.contains(TEST_MESSAGE[3]));
    }

    @Test
    public abstract void testAddDuplicateParts() throws Exception;

    @Test
    public abstract void testAddDuplicateIdentifiers() throws Exception;

    @Test
    public abstract void testSignSomeRedactable() throws Exception;

}
