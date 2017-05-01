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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public abstract class GLRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private final RedactableSignature glrss;
    private Node root;
    private final Map<ByteArray, Pointer> pointers = new HashMap<>();
    private final List<String> uris = new ArrayList<>();
    private final Set<String> redactUris = new HashSet<>();

    protected GLRedactableXMLSignature(RedactableSignature glrss) throws RedactableXMLSignatureException {
        super();
        this.glrss = glrss;
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        reset();
        glrss.initSign(keyPair, random);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        reset();
        glrss.initVerify(publicKey);
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        reset();
        glrss.initRedact(publicKey);
    }

    private void reset() {
        root = null;
        pointers.clear();
        uris.clear();
        redactUris.clear();
    }

    @Override
    public void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        Pointer pointer = new Pointer(uri, isRedactable);
        pointers.put(new ByteArray(pointer.getConcatDereference(root)), pointer);
        try {
            glrss.addPart(pointer.getConcatDereference(root), isRedactable);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException {
        if (!redactUris.add(uri)) {
            throw new RedactableXMLSignatureException("A URI cannot be added twice");
        }
    }

    @Override
    public void engineSetRootNode(Node root) {
        this.root = root;
    }

    @Override
    public Document engineSign() throws RedactableXMLSignatureException {
        GLRSSSignatureOutput output;
        try {
            output = (GLRSSSignatureOutput) glrss.sign();
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        return marshall(output);
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        try {
            return glrss.verify(unmarshall());
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public Document engineRedact() throws RedactableXMLSignatureException {
        GLRSSSignatureOutput redacted;
        GLRSSSignatureOutput original = unmarshall();

        for (String uri : redactUris) {
            Pointer pointer = new Pointer(uri, true);
            try {
                glrss.addIdentifier(new Identifier(pointer.getConcatDereference(root), uris.indexOf(uri)));
            } catch (RedactableSignatureException e) {
                throw new RedactableXMLSignatureException(e);
            }
        }

        try {
            redacted = (GLRSSSignatureOutput) glrss.redact(original);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        removeNodes(root, redactUris);
        root.removeChild(getSignatureNode(root));

        return marshall(redacted);
    }

    private Document marshall(GLRSSSignatureOutput output) throws RedactableXMLSignatureException {
        Signature<GSSignatureValue, GLProof> sigElement = new Signature<>(GSSignatureValue.class, GLProof.class);

        byte[] accumulatorValue = output.getGsAccumulator();
        byte[] dSigValue = output.getGsDsigValue();
        sigElement.setSignatureValue(new GSSignatureValue(dSigValue, accumulatorValue));

        List<GLRSSSignatureOutput.GLRSSSignedPart> signedParts = output.getParts();
        for (GLRSSSignatureOutput.GLRSSSignedPart signedPart : signedParts) {
            GLProof proof = new GLProof(signedPart);
            Pointer pointer = pointers.get(new ByteArray(signedPart.getMessagePart()));
            sigElement.addReference(new Reference<>(pointer, proof));
        }

        try {
            return sigElement.marshall(getOwnerDocument(root));
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private GLRSSSignatureOutput unmarshall() throws RedactableXMLSignatureException {
        Signature<GSSignatureValue, GLProof> signature;
        Node signatureNode = getSignatureNode(root);

        try {
            signature = Signature.unmarshall(GSSignatureValue.class, GLProof.class, signatureNode);
        } catch (JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }

        List<Reference<GLProof>> references = signature.getReferences();
        GLRSSSignatureOutput.Builder builder = new GLRSSSignatureOutput.Builder(references.size());
        for (int i = 0; i < references.size(); i++) {
            Pointer pointer = references.get(i).getPointer();
            pointers.put(new ByteArray(pointer.getConcatDereference(root)), pointer);
            uris.add(pointer.getUri());
            GLProof proof = references.get(i).getProof();
            builder.setMessagePart(i, pointer.getConcatDereference(root))
                    .setRedactable(i, pointer.isRedactable())
                    .setRandomValue(i, proof.getRandomValue())
                    .setAccValue(i, proof.getAccumulatorValue())
                    .setWitnesses(i, proof.getWitnesses())
                    .setGSProof(i, proof.getGsProof());
        }

        GSSignatureValue signatureValue = signature.getSignatureValue();
        builder.setGSAccumulator(signatureValue.getAccumulatorValue())
                .setGSDsigValue(signatureValue.getDSigValue());

        return builder.build();
    }

    public static class GLRSSwithBPAccumulatorAndRSA extends GLRedactableXMLSignature {
        public GLRSSwithBPAccumulatorAndRSA() throws RedactableXMLSignatureException, NoSuchAlgorithmException {
            super(RedactableSignature.getInstance("GLRSSwithRSAandBPA"));
        }
    }

}
