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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRedactableSignature;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Wolfgang Popp
 */
public abstract class GLRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private final RedactableSignature glrss;
    private Node root;
    private final Map<ByteArray, Pointer> pointers = new HashMap<>();

    protected GLRedactableXMLSignature(RedactableSignature glrss) throws RedactableXMLSignatureException {
        super();
        this.glrss = glrss;
    }

    @Override
    public void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException {
        glrss.initSign(keyPair, random);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        glrss.initVerify(publicKey);
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        glrss.initRedact(publicKey);
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

        Signature<GSSignatureValue, GLProof> sigElement = new Signature<>(GSSignatureValue.class, GLProof.class);

        byte[] accumulatorValue = output.getGsrssOutput().getAccumulatorValue();
        byte[] dSigValue = output.getGsrssOutput().getDSigValue();
        sigElement.setSignatureValue(new GSSignatureValue(accumulatorValue, dSigValue));

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

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        return false;
    }

    @Override
    public Document engineRedact() throws RedactableXMLSignatureException {
        return null;
    }

    public static class GLRSSwithBPAccumulatorAndRSA extends GLRedactableXMLSignature {
        public GLRSSwithBPAccumulatorAndRSA() throws RedactableXMLSignatureException, NoSuchAlgorithmException {
            super(RedactableSignature.getInstance("GLRSSwithRSAandBPA"));
        }
    }

}
