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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Reference;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Signature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.SimpleProof;
import org.w3c.dom.Document;
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
public class GSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private final RedactableSignature gsrss;
    private Node root;
    private Map<ByteArray, Pointer> pointers = new HashMap<>();
    private Set<String> redactUris = new HashSet<>();


    protected GSRedactableXMLSignature(RedactableSignature gsrss) throws RedactableXMLSignatureException {
        super();
        this.gsrss = gsrss;
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        reset();
        gsrss.initSign(keyPair, random);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        gsrss.initVerify(publicKey);
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        gsrss.initRedact(publicKey);
    }

    @Override
    public void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        Pointer pointer = new Pointer(uri, isRedactable);
        if (pointers.put(new ByteArray(pointer.getConcatDereference(root)), pointer) != null) {
            throw new RedactableXMLSignatureException("Cannot add the given URI twice");
        }
        try {
            gsrss.addPart(pointer.getConcatDereference(root), isRedactable);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException {
        if (!redactUris.add(uri)) {
            throw new RedactableXMLSignatureException("Cannot add the given URI twice");
        }
        try {
            gsrss.addIdentifier(new Identifier(new Pointer(uri).getConcatDereference(root)));
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

        return marshall(output);
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        try {
            return gsrss.verify(unmarshall());
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public Document engineRedact() throws RedactableXMLSignatureException {
        GSRSSSignatureOutput redacted;
        GSRSSSignatureOutput original = unmarshall();

        try {
            redacted = (GSRSSSignatureOutput) gsrss.redact(original);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        removeNodes(root, redactUris);
        root.removeChild(getSignatureNode(root));

        return marshall(redacted);
    }


    private Document marshall(GSRSSSignatureOutput output) throws RedactableXMLSignatureException {
        Signature<GSSignatureValue, SimpleProof> sigElement = new Signature<>(GSSignatureValue.class, SimpleProof.class);
        sigElement.setSignatureValue(new GSSignatureValue(output.getDSigValue(), output.getAccumulatorValue()));

        Map<ByteArray, byte[]> parts = output.getParts();
        for (Map.Entry<ByteArray, byte[]> signedPart : parts.entrySet()) {
            SimpleProof proof = new SimpleProof(signedPart.getValue());
            Pointer pointer = pointers.get(signedPart.getKey());
            Reference<SimpleProof> reference = new Reference<>(pointer, proof);
            sigElement.addReference(reference);
        }

        try {
            return sigElement.marshall(getOwnerDocument(root));
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private GSRSSSignatureOutput unmarshall() throws RedactableXMLSignatureException {
        Signature<GSSignatureValue, SimpleProof> signature;
        Node signatureNode = getSignatureNode(root);

        try {
            signature = Signature.unmarshall(GSSignatureValue.class, SimpleProof.class, signatureNode);
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }

        GSSignatureValue signatureValue = signature.getSignatureValue();
        List<Reference<SimpleProof>> references = signature.getReferences();
        GSRSSSignatureOutput.Builder builder = new GSRSSSignatureOutput.Builder()
                .setAccumulatorValue(signatureValue.getAccumulatorValue())
                .setDSigValue(signatureValue.getDSigValue());

        for (Reference<SimpleProof> reference : references) {
            Pointer pointer = reference.getPointer();
            pointers.put(new ByteArray(pointer.getConcatDereference(root)), pointer);
            builder.addSignedPart(new ByteArray(pointer.getConcatDereference(root)),
                    reference.getProof().getBytes(), pointer.isRedactable());
        }

        return builder.build();
    }

    private void reset() {
        root = null;
        pointers.clear();
    }

    public static class GSRSSwithBPAccumulatorAndRSA extends GSRedactableXMLSignature {
        public GSRSSwithBPAccumulatorAndRSA() throws NoSuchAlgorithmException, RedactableXMLSignatureException {
            super(RedactableSignature.getInstance("GSRSSwithRSAandBPA"));
        }
    }
}
