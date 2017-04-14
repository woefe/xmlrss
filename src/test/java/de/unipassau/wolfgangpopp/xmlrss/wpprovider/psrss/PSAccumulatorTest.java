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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Accumulator;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorState;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.assertTrue;

/**
 * @author Wolfgang Popp
 */
public class PSAccumulatorTest {
    private static KeyPair keyPair;

    static {
        Security.insertProviderAt(new WPProvider(), 0);
        PSRSSPublicKey publicKey256 = new PSRSSPublicKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412906735607605108373982421012500888307062421310001762155422489671132976679912849"));
        PSRSSPrivateKey privateKey256 = new PSRSSPrivateKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412734960638035580933850038621738468566657503090109097536944629352405060890801636"));
        keyPair = new KeyPair(publicKey256, privateKey256);
    }

    @Test
    public void testCreateWitness() throws Exception {
        byte[][] message = {
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes(),
        };
        Accumulator psa = Accumulator.getInstance("PSA");
        psa.initWitness(keyPair);
        psa.digest(message);
        byte[] witness = psa.createWitness(message[0]);

        psa.initVerify(keyPair.getPublic());
        psa.restoreVerify(psa.getAccumulatorValue());
        assertTrue(psa.verify(witness, message[0]));
    }

    @Test
    public void testRestoreWitness() throws Exception {
        byte[][] message = {
                "test1".getBytes(),
                "test2".getBytes(),
                "test3".getBytes(),
                "test4".getBytes(),
                "test5".getBytes(),
        };
        Accumulator psa = Accumulator.getInstance("PSA");
        psa.initWitness(keyPair);
        psa.digest(message);
        byte[] witness0 = psa.createWitness(message[0]);
        AccumulatorState savedState = psa.getAccumulatorState();

        // restore using saved state
        psa = Accumulator.getInstance("PSA");
        psa.initWitness(keyPair);
        psa.restoreWitness(savedState);
        byte[] witness1 = psa.createWitness(message[1]);
        byte[] accumulatorValue = psa.getAccumulatorValue();
        byte[] auxiliaryValue = psa.getAuxiliaryValue();

        // restore using aux and acc
        psa = Accumulator.getInstance("PSA");
        psa.initWitness(keyPair);
        psa.restoreWitness(accumulatorValue, auxiliaryValue);
        byte[] witness2 = psa.createWitness(message[2]);

        psa = Accumulator.getInstance("PSA");
        psa.initVerify(keyPair.getPublic());
        psa.restoreVerify(accumulatorValue);
        assertTrue(psa.verify(witness0, message[0]));
        assertTrue(psa.verify(witness1, message[1]));
        assertTrue(psa.verify(witness2, message[2]));
    }

}