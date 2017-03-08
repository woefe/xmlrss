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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableXMLSignatureSpi;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.URIDereferencer;
import org.jcp.xml.dsig.internal.dom.DOMUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.xpath.XPathExpressionException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    private RedactableSignature signature;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private Node root;
    private Map<String, byte[]> selectorResults = new HashMap<>();

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
    public void engineSetRootNode(Node node) {
        root = node;
    }

    @Override
    //TODO remove xpathexception
    public void engineAddPartSelector(String uri) throws XMLSignatureException, XPathExpressionException, SignatureException {
        if (root == null) {
            throw new XMLSignatureException("root node not set");
        }
        byte[] data = URIDereferencer.dereference(root, uri).getBytes();
        selectorResults.put(uri, data);
        signature.addPart(data);
    }

    @Override
    public void engineSign() throws XMLSignatureException, SignatureException {
        PSSignatureOutput output = (PSSignatureOutput) signature.sign();

        Base64.Encoder base64 = Base64.getEncoder();
        Document doc = DOMUtils.getOwnerDocument(root);
        Element signature = doc.createElementNS(RedactableXMLSignature.XML_NAMESPACE, "Signature");
        Element references = doc.createElement("References");
        Element signatureValue = doc.createElement("SignatureValue");

        for (String selector : selectorResults.keySet()) {
            Element reference = doc.createElement("Reference");
            reference.setAttribute("URI", selector);
            Element proof = doc.createElement("Proof");
            proof.appendChild(doc.createTextNode(base64.encodeToString(output.getProof(selectorResults.get(selector)))));
            reference.appendChild(proof);
            references.appendChild(reference);
        }

        Element tag = doc.createElement("Tag");
        tag.appendChild(doc.createTextNode(base64.encodeToString(output.getTag())));
        signatureValue.appendChild(tag);

        Element proofOfTag = doc.createElement("ProofOfTag");
        proofOfTag.appendChild(doc.createTextNode(base64.encodeToString(output.getProofOfTag())));
        signatureValue.appendChild(proofOfTag);

        signature.appendChild(references);
        signature.appendChild(signatureValue);
        root.appendChild(signature);
    }

    @Override
    public boolean engineVerify() {
        return false;
    }

    @Override
    public void engineRedact() {

    }

    private void reset() {
        selectorResults.clear();
        root = null;
    }

    public static class XMLPSRSSwithPSA extends PSRedactableXMLSignature {
        public XMLPSRSSwithPSA() throws NoSuchAlgorithmException {
            super(RedactableSignature.getInstance("PSRSSwithPSA"));
        }
    }
}
