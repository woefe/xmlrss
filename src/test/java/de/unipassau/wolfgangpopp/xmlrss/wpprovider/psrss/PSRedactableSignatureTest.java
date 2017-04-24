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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AbstractRSSTest;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSRedactableSignatureTest extends AbstractRSSTest {

    public PSRedactableSignatureTest() throws NoSuchAlgorithmException {
        super("RSSwithPSA", new WPProvider(), new KeyPair(
                new PSRSSPublicKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412906735607605108373982421012500888307062421310001762155422489671132976679912849")),
                new PSRSSPrivateKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412734960638035580933850038621738468566657503090109097536944629352405060890801636"))
        ));
    }

    @Test(expected = PSRSSException.class)
    public void testAddDuplicateParts() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance(algorithm);
        rssWithPSA.initSign(keyPair);

        rssWithPSA.addPart("test1".getBytes());
        rssWithPSA.addPart("test2".getBytes());
        rssWithPSA.addPart("test2".getBytes());
    }

    @Override
    @Test(expected = RedactableSignatureException.class)
    public void testAddDuplicateIdentifiers() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance(algorithm);
        Identifier identifier = new Identifier("test".getBytes());
        rssWithPSA.initRedact(keyPair.getPublic());
        rssWithPSA.addIdentifier(identifier);
        rssWithPSA.addIdentifier(identifier);
    }

    @Override
    @Test(expected = RedactableSignatureException.class)
    public void testSignSomeRedactable() throws Exception {
        RedactableSignature rssWithPSA = RedactableSignature.getInstance(algorithm);
        rssWithPSA.initSign(keyPair);
        rssWithPSA.addPart("test".getBytes(), false);
    }

    @Test
    public void testMerge() throws Exception {
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
    public void testUpdate() throws Exception {
        RedactableSignature rss = RedactableSignature.getInstance("RSSwithPSA");

        rss.initSign(keyPair);
        rss.addPart("test1".getBytes());
        rss.addPart("test2".getBytes());
        rss.addPart("test3".getBytes());
        SignatureOutput signedMessage = rss.sign();

        rss.initUpdate(keyPair);
        rss.addPart("test4".getBytes());
        rss.addPart("test5".getBytes());
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
}