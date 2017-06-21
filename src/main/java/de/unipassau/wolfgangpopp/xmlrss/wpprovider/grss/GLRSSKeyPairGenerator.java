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
public abstract class GLRSSKeyPairGenerator extends KeyPairGeneratorSpi {
    private final String algorithm;
    private final KeyPairGenerator gsrssGenerator;
    private final KeyPairGenerator accGenerator;

    protected GLRSSKeyPairGenerator(String algorithm, KeyPairGenerator gsrssGenerator, KeyPairGenerator accGenerator) {
        this.algorithm = algorithm;
        this.gsrssGenerator = gsrssGenerator;
        this.accGenerator = accGenerator;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        gsrssGenerator.initialize(keysize, random);
        accGenerator.initialize(keysize, random);
    }

    @Override
    public KeyPair generateKeyPair() {
        KeyPair gsrssKeyPair = gsrssGenerator.generateKeyPair();
        KeyPair accKeyPair = accGenerator.generateKeyPair();
        PublicKey publicKey = new GLRSSPublicKey(algorithm, gsrssKeyPair.getPublic(), accKeyPair.getPublic());
        PrivateKey privateKey = new GLRSSPrivateKey(algorithm, gsrssKeyPair.getPrivate(), accKeyPair.getPrivate());
        return new KeyPair(publicKey, privateKey);
    }

    public static class GLRSSwithRSAandBPA extends GLRSSKeyPairGenerator {
        public GLRSSwithRSAandBPA() throws NoSuchAlgorithmException {
            super("GLRSSwithRSAandBPA", KeyPairGenerator.getInstance("GSRSSwithRSAandBPA"),
                    KeyPairGenerator.getInstance("BPA"));
        }
    }
}
