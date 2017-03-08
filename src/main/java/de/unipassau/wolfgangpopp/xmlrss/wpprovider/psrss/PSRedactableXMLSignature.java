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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.URIDereferencer;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.xpath.XPathExpressionException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private RedactableSignature signature;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private Node root;
    private List<String> selectors = new LinkedList<>();

    PSRedactableXMLSignature(RedactableSignature signature) {
        this.signature = signature;
    }

    @Override
    public void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
        engineInitSign(keyPair, new SecureRandom());
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        signature.initSign(keyPair, random);
        this.keyPair = keyPair;
        this.publicKey = keyPair.getPublic();
        reset();
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        signature.initVerify(publicKey);
        this.publicKey = publicKey;
        reset();
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        signature.initRedact(publicKey);
        this.publicKey = publicKey;
        reset();
    }

    @Override
    public void engineAddPartSelector(String uri) {
        selectors.add(uri);
    }

    @Override
    public void engineSetRootNode(Node node) {
        root = node;
    }

    @Override
    public void engineSign() throws XMLSignatureException, SignatureException {
        /*
        for (String selector : selectors) {
            try {
                signature.addPart(URIDereferencer.dereference(root, selector).getBytes());
            } catch (SignatureException | XPathExpressionException e) {
                throw new XMLSignatureException(e);
            }
        }
        PSSignatureOutput output = (PSSignatureOutput) signature.sign();
        root.
        root.appendChild()
        //TODO Marshall output
        */
    }

    @Override
    public boolean engineVerify() {
        return false;
    }

    @Override
    public void engineRedact() {

    }

    private void reset() {
        selectors.clear();
        root = null;
    }

    public static class XMLPSRSSwithPSA extends PSRedactableXMLSignature {
        public XMLPSRSSwithPSA() throws NoSuchAlgorithmException {
            super(RedactableSignature.getInstance("PSRSSwithPSA"));
        }
    }
}
