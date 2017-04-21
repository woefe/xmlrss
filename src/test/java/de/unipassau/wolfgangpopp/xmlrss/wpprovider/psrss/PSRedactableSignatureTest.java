/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2016 Wolfgang Popp
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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableSignatureTest {

    private static KeyPair keyPair;

    static {
        Security.insertProviderAt(new WPProvider(), 0);
        PSRSSPublicKey publicKey256 = new PSRSSPublicKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412906735607605108373982421012500888307062421310001762155422489671132976679912849"));
        PSRSSPrivateKey privateKey256 = new PSRSSPrivateKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412734960638035580933850038621738468566657503090109097536944629352405060890801636"));
        keyPair = new KeyPair(publicKey256, privateKey256);
    }

    public PSRedactableSignatureTest() throws NoSuchAlgorithmException {
    }

    @Test
    public void getInstance() throws Exception {
        RedactableSignature rss1 = RedactableSignature.getInstance("RSSwithPSA");
        assertEquals(rss1.getAlgorithm(), "RSSwithPSA");
    }

    @Test
    public void engineSign() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test1".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);

        SignatureOutput signature = rssWithPSA.sign();

        assertTrue(signature.containsAll("test1".getBytes(), "test2".getBytes()));
        assertEquals(signature.size(), 2);
    }

    @Test(expected = PSRSSException.class)
    public void engineAddPartDuplicates() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test1".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);
    }

    @Test
    public void engineVerify() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance("RSSwithPSA");
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test3".getBytes(), false);
        rssWithPSA.addPart("test2".getBytes(), false);
        rssWithPSA.addPart("test4".getBytes(), false);

        SignatureOutput signature = rssWithPSA.sign();

        rssWithPSA.initVerify(keyPair.getPublic());
        assertTrue(rssWithPSA.verify(signature));
    }

    @Test
    public void engineRedact() throws Exception {
        byte[][] message = {
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes(),
        };

        Identifier[] identifiers = new Identifier[message.length];

        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");
        rss.initSign(keyPair);
        for (int i = 0; i < message.length; i++) {
            identifiers[i] = rss.addPart(message[i]);
        }
        SignatureOutput signedMessage = rss.sign();

        rss.initRedact(keyPair.getPublic());
        rss.addIdentifier(identifiers[1]);
        rss.addIdentifier(identifiers[0]);
        SignatureOutput redactedMessage = rss.redact(signedMessage);

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(redactedMessage));
        assertFalse(redactedMessage.contains(message[0]));
        assertFalse(redactedMessage.contains(message[1]));
    }

    @Test
    public void testRedactAndVerify() throws Exception {

        RedactableSignature sig =
                RedactableSignature.getInstance("PSRSSwithPSA");

        sig.initSign(keyPair);
        sig.addPart("Data to sign\n".getBytes(), true);
        Identifier identifier = sig.addPart("More data to sign".getBytes(), true);
        SignatureOutput out = sig.sign();

        sig.initRedact(keyPair.getPublic());
        sig.addIdentifier(identifier);
        SignatureOutput redacted = sig.redact(out);

        sig.initVerify(keyPair.getPublic());
        boolean isRedactedValid = sig.verify(redacted);
        boolean isOriginalValid = sig.verify(out);

        assertTrue(isRedactedValid);
        assertTrue(isOriginalValid);
    }

    @Test
    public void engineMerge() throws Exception {
        byte[][] message = {
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes(),
        };

        Identifier[] identifiers = new Identifier[message.length];

        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");

        rss.initSign(keyPair);
        for (int i = 0; i < message.length; i++) {
            identifiers[i] = rss.addPart(message[i]);
        }
        SignatureOutput wholeMessage = rss.sign();

        rss.initRedact(keyPair.getPublic());
        rss.addIdentifier(identifiers[3]);
        rss.addIdentifier(identifiers[4]);
        SignatureOutput redacted1 = rss.redact(wholeMessage);

        rss.initRedact(keyPair.getPublic());
        rss.addIdentifier(identifiers[1]);
        rss.addIdentifier(identifiers[2]);
        SignatureOutput redacted2 = rss.redact(wholeMessage);

        rss.initMerge(keyPair.getPublic());
        SignatureOutput merged = rss.merge(redacted1, redacted2);
        assertTrue(merged.containsAll(message));
    }

    @Test
    public void engineUpdate() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");

        rss.initSign(keyPair);
        rss.addPart("test1".getBytes(), false);
        rss.addPart("test2".getBytes(), false);
        rss.addPart("test3".getBytes(), false);
        SignatureOutput signedMessage = rss.sign();

        rss.initUpdate(keyPair);
        rss.addPart("test4".getBytes(), false);
        rss.addPart("test5".getBytes(), false);
        SignatureOutput updated = rss.update(signedMessage);

        rss.initVerify(keyPair.getPublic());
        assertTrue(rss.verify(updated));
        assertEquals(updated.size(), 5);
        assertTrue(updated.containsAll(
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes()
        ));
    }

    @Test
    public void signAndThenSign() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");

        rss.initSign(keyPair);
        rss.addPart("test1".getBytes(), false);
        SignatureOutput output1 = rss.sign();

        rss.addPart("test2".getBytes(), false);
        SignatureOutput output2 = rss.sign();

        assertTrue(output1.contains("test1".getBytes()));
        assertTrue(output2.contains("test2".getBytes()));
        assertFalse(output2.contains("test1".getBytes()));
    }
}