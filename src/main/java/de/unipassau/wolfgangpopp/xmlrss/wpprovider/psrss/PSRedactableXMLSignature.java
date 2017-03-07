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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableXMLSignatureSpi;
import org.w3c.dom.Node;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private RedactableSignature signature;

    PSRedactableXMLSignature(RedactableSignature signature) {
        this.signature = signature;
    }

    @Override
    public void engineInitSign(KeyPair keyPair) {

    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) {

    }

    @Override
    public void engineInitVerify(PublicKey publicKey) {

    }

    @Override
    public void engineInitRedact(PublicKey publicKey) {

    }

    @Override
    public void engineSign() {

    }

    @Override
    public void engineAddPartSelector(String uri) {

    }

    @Override
    public void engineSetRootNode(Node node) {

    }

    @Override
    public boolean engineVerify() {
        return false;
    }

    @Override
    public void engineRedact() {

    }

    public static class XMLPSRSSwithPSA extends PSRedactableXMLSignature {
        public XMLPSRSSwithPSA() throws NoSuchAlgorithmException {
            super(RedactableSignature.getInstance("PSRSSwithPSA"));
        }
    }
}
