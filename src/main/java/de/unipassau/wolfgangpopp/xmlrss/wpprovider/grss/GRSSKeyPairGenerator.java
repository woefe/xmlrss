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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @author Wolfgang Popp
 */
public abstract class GRSSKeyPairGenerator extends KeyPairGeneratorSpi {

    private final KeyPairGenerator dsigGenerator;
    private final KeyPairGenerator accGenerator;
    private final String algorithm;

    protected GRSSKeyPairGenerator(String algorithm, KeyPairGenerator dsigGenerator, KeyPairGenerator accGenerator) {
        this.dsigGenerator = dsigGenerator;
        this.accGenerator = accGenerator;
        this.algorithm = algorithm;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        dsigGenerator.initialize(keysize, random);
        accGenerator.initialize(keysize, random);
    }

    @Override
    public KeyPair generateKeyPair() {
        KeyPair dsigKeyPair = dsigGenerator.generateKeyPair();
        KeyPair accKeyPair = accGenerator.generateKeyPair();
        PublicKey publicKey = new GRSSPublicKey(algorithm, dsigKeyPair.getPublic(), accKeyPair.getPublic());
        PrivateKey privateKey = new GRSSPrivateKey(algorithm, dsigKeyPair.getPrivate(), accKeyPair.getPrivate());
        return new KeyPair(publicKey, privateKey);
    }


    public static class GRSSwithRSAandBPA extends GRSSKeyPairGenerator {
        public GRSSwithRSAandBPA() throws NoSuchAlgorithmException {
            super("GRSSwithRSAandBPAcc", KeyPairGenerator.getInstance("RSA"), KeyPairGenerator.getInstance("BPA"));
        }
    }

}
