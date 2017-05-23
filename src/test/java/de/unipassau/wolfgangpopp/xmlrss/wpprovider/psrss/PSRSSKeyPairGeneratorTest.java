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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.assertEquals;

/**
 * @author Wolfgang Popp
 */
public class PSRSSKeyPairGeneratorTest {
    // TODO fix this test. The key pair generator generates keys of the wrong size sometimes!!
    //@Test
    public void generateKeyPair() throws Exception {
        KeyPairGenerator psrssKeyGen = KeyPairGenerator.getInstance("PSRSS", new WPProvider());
        psrssKeyGen.initialize(512);
        KeyPair keyPair = psrssKeyGen.generateKeyPair();
        assertEquals(512, ((PSRSSPrivateKey) keyPair.getPrivate()).getKey().bitLength());
        assertEquals(512, ((PSRSSPublicKey) keyPair.getPublic()).getKey().bitLength());

        psrssKeyGen.initialize(513);
        keyPair = psrssKeyGen.generateKeyPair();
        assertEquals(513, ((PSRSSPrivateKey) keyPair.getPrivate()).getKey().bitLength());
        assertEquals(513, ((PSRSSPublicKey) keyPair.getPublic()).getKey().bitLength());
    }

}