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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureSpi;
import org.jcp.xml.dsig.internal.dom.DOMUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    public static final String XML_NAMESPACE = "http://sec.uni-passau.de/2017/03/xmlpsrss";
    private RedactableSignature signature;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private Node root;
    private Map<Element, byte[]> selectorResults = new HashMap<>();

    PSRedactableXMLSignature(RedactableSignature signature) throws RedactableXMLSignatureException {
        super();
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
    public void engineAddPartSelector(String uri) throws RedactableXMLSignatureException {
        if (root == null) {
            throw new RedactableXMLSignatureException("root node not set");
        }
        //TODO Improvement: Selector results not needed for verification and redaction
        // Could however be used to check if uri is valid.
        byte[] data = canonicalize(dereference(uri, root));

        Document doc = DOMUtils.getOwnerDocument(root);
        Element pointer = doc.createElementNS(XML_NAMESPACE, "Pointer");
        pointer.setAttribute("URI", uri);

        byte[] pointerConcatData = concat(pointer, data);

        selectorResults.put(pointer, pointerConcatData);
        try {
            signature.addPart(pointerConcatData);
        } catch (SignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private byte[] concat(Node pointer, byte[] data) throws RedactableXMLSignatureException {
        byte[] c14nPointer = canonicalize(pointer);
        byte[] pointerConcatData = new byte[c14nPointer.length + data.length];
        System.arraycopy(c14nPointer, 0, pointerConcatData, 0, c14nPointer.length);
        System.arraycopy(data, 0, pointerConcatData, c14nPointer.length, data.length);

        return pointerConcatData;
    }

    @Override
    public void engineSign() throws RedactableXMLSignatureException {
        PSSignatureOutput output;
        try {
            output = (PSSignatureOutput) signature.sign();
        } catch (SignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        Base64.Encoder base64 = Base64.getEncoder();
        Document doc = DOMUtils.getOwnerDocument(root);
        Element signature = doc.createElementNS(XML_NAMESPACE, "Signature");
        Element references = doc.createElementNS(XML_NAMESPACE,"References");
        Element signatureValue = doc.createElementNS(XML_NAMESPACE, "SignatureValue");

        for (Element pointer : selectorResults.keySet()) {
            Element reference = doc.createElementNS(XML_NAMESPACE, "Reference");

            Element proof = doc.createElementNS(XML_NAMESPACE, "Proof");
            proof.appendChild(doc.createTextNode(base64.encodeToString(output.getProof(selectorResults.get(pointer)))));

            reference.appendChild(pointer);
            reference.appendChild(proof);
            references.appendChild(reference);
        }

        Element tag = doc.createElementNS(XML_NAMESPACE,"Tag");
        tag.appendChild(doc.createTextNode(base64.encodeToString(output.getTag())));
        signatureValue.appendChild(tag);

        Element proofOfTag = doc.createElementNS(XML_NAMESPACE,"ProofOfTag");
        proofOfTag.appendChild(doc.createTextNode(base64.encodeToString(output.getProofOfTag())));
        signatureValue.appendChild(proofOfTag);

        Element accumulator = doc.createElementNS(XML_NAMESPACE, "Accumulator");
        accumulator.appendChild(doc.createTextNode(base64.encodeToString(output.getAccumulator())));
        signatureValue.appendChild(accumulator);

        signature.appendChild(references);
        signature.appendChild(signatureValue);
        root.appendChild(signature);
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        Base64.Decoder base64 = Base64.getDecoder();

        //TODO Check returned nodes are indeed as expected
        Document doc = DOMUtils.getOwnerDocument(root);
        Node signatureNode = doc.getElementsByTagNameNS(XML_NAMESPACE, "Signature").item(0);

        // Enveloped signature; remove signature node from document, before doing any further processing
        root.removeChild(signatureNode);

        Node references = signatureNode.getFirstChild();
        Node signatureValue = references.getNextSibling();

        Node tagNode = signatureValue.getFirstChild();
        Node proofOfTagNode = tagNode.getNextSibling();
        Node accumulatorNode = proofOfTagNode.getNextSibling();

        byte[] tag = base64.decode(tagNode.getFirstChild().getNodeValue());
        byte[] proofOfTag = base64.decode(proofOfTagNode.getFirstChild().getNodeValue());
        byte[] accumulator = base64.decode(accumulatorNode.getFirstChild().getNodeValue());

        PSSignatureOutput.Builder builder = new PSSignatureOutput.Builder(tag, proofOfTag, accumulator);

        NodeList referencesList = references.getChildNodes();
        for (int i = 0; i < referencesList.getLength(); i++) {
            Node node = referencesList.item(i);
            Node pointer = node.getFirstChild();
            if (node.getNodeName().equals("Reference") && pointer != null && pointer.getNodeName().equals("Pointer")) {
                Node proofNode = pointer.getNextSibling(); // TODO Check if actually proofnode
                String uri = pointer.getAttributes().getNamedItem("URI").getTextContent();
                byte[] part = canonicalize(dereference(uri, root));
                byte[] proof = base64.decode(proofNode.getTextContent().getBytes());
                builder.add(concat(pointer, part), proof);
            }
            // TODO else throw exception
        }

        // TODO Copy root and do processing on copy instead of deleting/adding the signature node
        root.appendChild(signatureNode);

        PSSignatureOutput signatureOutput = builder.build();
        try {
            return signature.verify(signatureOutput);
        } catch (SignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public void engineRedact() {
        Document doc = DOMUtils.getOwnerDocument(root);
        Node signatureNode = doc.getElementsByTagNameNS(XML_NAMESPACE, "Signature").item(0);

        Node references = signatureNode.getFirstChild();
        NodeList referencesList = references.getChildNodes();

        Set<Element> elements = selectorResults.keySet();

        Set<String> selectors = new HashSet<>();

        for (Element element : elements) {
            selectors.add(element.getAttribute("URI"));
        }

        for (int i = 0; i < referencesList.getLength(); i++) {
            Node reference = referencesList.item(i);
            Node pointer = reference.getFirstChild();
            if (reference.getNodeName().equals("Reference") && pointer != null && pointer.getNodeName().equals("Pointer")) {
                String uri = pointer.getAttributes().getNamedItem("URI").getTextContent();
                if (selectors.contains(uri)) {
                    references.removeChild(reference);
                }
            }
        }
    }

    private void reset() {
        selectorResults.clear();
        root = null;
    }

    public static class XMLPSRSSwithPSA extends PSRedactableXMLSignature {
        public XMLPSRSSwithPSA() throws NoSuchAlgorithmException, RedactableXMLSignatureException {
            super(RedactableSignature.getInstance("PSRSSwithPSA"));
        }
    }
}
