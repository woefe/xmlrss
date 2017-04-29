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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Signature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.SimpleProof;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private RedactableSignature psrss;
    private Node root;
    private Map<ByteArray, Pointer> pointers = new HashMap<>();
    private Set<String> redactUris = new HashSet<>();

    PSRedactableXMLSignature(RedactableSignature signature) throws RedactableXMLSignatureException {
        super();
        this.psrss = signature;
    }

    @Override
    public void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
        engineInitSign(keyPair, new SecureRandom());
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        reset();
        psrss.initSign(keyPair, random);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        psrss.initVerify(publicKey);
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        psrss.initRedact(publicKey);
    }

    @Override
    public void engineSetRootNode(Node node) {
        root = node;
    }

    @Override
    public void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException {
        if (!redactUris.add(uri)) {
            throw new RedactableXMLSignatureException("A URI cannot be added twice");
        }
        try {
            psrss.addIdentifier(new Identifier(new Pointer(uri).getConcatDereference(root)));
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        if (root == null) { //TODO move to superclass?
            throw new RedactableXMLSignatureException("root node not set");
        }

        Pointer pointer = new Pointer(uri, isRedactable);
        if (pointers.put(new ByteArray(pointer.getConcatDereference(root)), pointer) != null) {
            throw new RedactableXMLSignatureException("An uri cannot be added twice");
        }

        try {
            psrss.addPart(pointer.getConcatDereference(root), isRedactable);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public Document engineSign() throws RedactableXMLSignatureException {
        PSSignatureOutput output;
        try {
            output = (PSSignatureOutput) psrss.sign();
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        return marshall(output);
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        try {
            return psrss.verify(unmarshall());
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public Document engineRedact() throws RedactableXMLSignatureException {
        PSSignatureOutput redacted;
        PSSignatureOutput original = unmarshall();

        try {
            redacted = (PSSignatureOutput) psrss.redact(original);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        removeNodes(root, redactUris);
        root.removeChild(getSignatureNode(root));

        return marshall(redacted);
    }

    private Document marshall(PSSignatureOutput output) throws RedactableXMLSignatureException {
        Signature<PSSignatureValue, SimpleProof> sigElement = new Signature<>(PSSignatureValue.class, SimpleProof.class);
        for (PSSignatureOutput.SignedPart signedPart : output) {
            SimpleProof proof = new SimpleProof(signedPart.getProof());
            Reference<SimpleProof> reference = new Reference<>(pointers.get(signedPart.getElement()), proof);
            sigElement.addReference(reference);
        }
        sigElement.setSignatureValue(new PSSignatureValue(output));
        try {
            return sigElement.marshall(getOwnerDocument(root));
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private PSSignatureOutput unmarshall() throws RedactableXMLSignatureException {
        Signature<PSSignatureValue, SimpleProof> unmarshalled;
        try {
            unmarshalled = Signature.unmarshall(PSSignatureValue.class, SimpleProof.class, getSignatureNode(root));
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }

        PSSignatureValue sigValue = unmarshalled.getSignatureValue();
        PSSignatureOutput.Builder builder = new PSSignatureOutput.Builder(sigValue.getTag(),
                sigValue.getProofOfTag(), sigValue.getAccumulator());

        List<Reference<SimpleProof>> references = unmarshalled.getReferences();
        for (Reference<SimpleProof> reference : references) {
            try {
                Pointer pointer = reference.getPointer();
                pointers.put(new ByteArray(pointer.getConcatDereference(root)), pointer);
                builder.add(pointer.getConcatDereference(root), reference.getProof().getBytes());
            } catch (PSRSSException e) {
                throw new RedactableXMLSignatureException(e);
            }
        }

        return builder.build();
    }

    private void reset() {
        root = null;
    }

    public static class XMLPSRSSwithPSA extends PSRedactableXMLSignature {
        public XMLPSRSSwithPSA() throws NoSuchAlgorithmException, RedactableXMLSignatureException {
            super(RedactableSignature.getInstance("PSRSSwithPSA"));
        }
    }
}
