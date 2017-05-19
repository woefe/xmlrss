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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.CryptoUtils.safePrime;

/**
 * @author Wolfgang Popp
 */
public class BPKeyPairGenerator extends KeyPairGeneratorSpi {


    private SecureRandom random = new SecureRandom();
    private int keySize = 2048;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        //TODO
        super.initialize(params, random);
    }

    @Override
    public KeyPair generateKeyPair() {
        BigInteger p = safePrime(keySize / 2, random);
        BigInteger q = safePrime(keySize / 2, random);

        while (p.equals(q)) {
            q = safePrime(keySize / 2, random);
        }

        PublicKey publicKey = new BPPublicKey(p.multiply(q));
        PrivateKey privateKey = new BPPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }
}
