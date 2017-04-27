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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.xml;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Signature;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public class GSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private final RedactableSignature gsrss;
    private Node root;
    private Set<Pointer> pointers = new HashSet<>();


    protected GSRedactableXMLSignature(RedactableSignature gsrss) throws RedactableXMLSignatureException {
        super();
        this.gsrss = gsrss;
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        gsrss.initSign(keyPair, random);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        gsrss.initVerify(publicKey);
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        gsrss.initRedact(publicKey);
    }

    @Override
    public void engineAddPartSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        Pointer pointer = new Pointer(root, uri, isRedactable);
        if (!pointers.add(pointer)) {
            throw new RedactableXMLSignatureException("Cannot add the given URI twice");
        }
        try {
            gsrss.addPart(pointer.getConcatDereference(), isRedactable);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public void engineSetRootNode(Node root) {
        this.root = root;
    }

    @Override
    public Document engineSign() throws RedactableXMLSignatureException {
        GSRSSSignatureOutput output;
        try {
            output = (GSRSSSignatureOutput) gsrss.sign();
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        Signature<GSSignatureValue, GSProof> sigElement = new Signature<>(GSSignatureValue.class, GSProof.class);

        for (Pointer pointer : pointers) {
            GSProof proof = new GSProof(output.getProof(new Identifier(pointer.getConcatDereference())));
            Reference<GSProof> reference = new Reference<>(pointer, proof);
            sigElement.addReference(reference);
        }
        sigElement.setSignatureValue(new GSSignatureValue(output.getDSigValue(), output.getAccumulatorValue()));

        try {
            return sigElement.marshall(getOwnerDocument(root));
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        return false;
    }

    @Override
    public void engineRedact() throws RedactableXMLSignatureException {

    }

    public static class GSRSSwithBPAccumulatorAndRSA extends GSRedactableXMLSignature {
        public GSRSSwithBPAccumulatorAndRSA() throws NoSuchAlgorithmException, RedactableXMLSignatureException {
            super(RedactableSignature.getInstance("GSRSSwithRSAandBPA"));
        }
    }
}
