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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Accumulator;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.Assert.*;

/**
 * @author Wolfgang Popp
 */
public class BPAccumulatorTest {

    static {
        Security.insertProviderAt(new WPProvider(), 0);
    }

    private KeyPair keyPair;

    @Before
    public void initialize() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("BPA");
        keyGen.initialize(512);
        keyPair = keyGen.generateKeyPair();
    }

    @Test
    public void testCreateAndVerifyWittness() throws Exception{
        byte[][] message = {
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes(),
        };


        Accumulator accumulator = Accumulator.getInstance("BPA");
        accumulator.initWitness(keyPair, message);
        byte[] witness = accumulator.createWitness(message[0]);

        accumulator.initVerify(keyPair.getPublic(), accumulator.getAccumulatorValue());
        assertTrue(accumulator.verify(witness, message[0]));


    }

}