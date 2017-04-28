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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureSpi;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
abstract class PSRedactableXMLSignature extends RedactableXMLSignatureSpi {

    public static final String XML_NAMESPACE = "http://sec.uni-passau.de/2017/03/xmlpsrss";
    private RedactableSignature signature;
    private Node root;
    private Map<Element, byte[]> selectorResults = new HashMap<>();
    private State state;

    private enum State { SIGN, REDACT, VERIFY }

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
        state = State.SIGN;
        reset();
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        signature.initVerify(publicKey);
        state = State.VERIFY;
        reset();
    }

    @Override
    public void engineInitRedact(PublicKey publicKey) throws InvalidKeyException {
        signature.initRedact(publicKey);
        state = State.REDACT;
        reset();
    }

    @Override
    public void engineSetRootNode(Node node) {
        root = node;
    }

    @Override
    public void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException {
        engineAddSignSelector(uri, true);
    }

    @Override
    public void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        if (root == null) {
            throw new RedactableXMLSignatureException("root node not set");
        }
        //TODO Improvement: Selector results not needed for verification and redaction
        // Could however be used to check if uri is valid.
        byte[] data = canonicalize(dereference(uri, root));

        Document doc = getOwnerDocument(root);
        Element pointer = doc.createElementNS(XML_NAMESPACE, "Pointer");
        pointer.setAttribute("URI", uri);

        byte[] pointerConcatData = concat(pointer, data);

        selectorResults.put(pointer, pointerConcatData);
        try {
            if (state == State.REDACT) {
                signature.addIdentifier(new Identifier(pointerConcatData));
            } else if (state == State.SIGN) {
                signature.addPart(pointerConcatData);
            }
            //throw new RedactableXMLSignatureException("")
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private byte[] concat(Node pointer, byte[] data) throws RedactableXMLSignatureException {
        return new ByteArray(canonicalize(pointer)).concat(data).getArray();
    }

    @Override
    public Document engineSign() throws RedactableXMLSignatureException {
        PSSignatureOutput output;
        try {
            output = (PSSignatureOutput) signature.sign();
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }

        Base64.Encoder base64 = Base64.getEncoder();
        Document doc = getOwnerDocument(root);
        Element signature = doc.createElementNS(XML_NAMESPACE, "Signature");
        Element references = doc.createElementNS(XML_NAMESPACE, "References");
        Element signatureValue = doc.createElementNS(XML_NAMESPACE, "SignatureValue");

        for (Element pointer : selectorResults.keySet()) {
            Element reference = doc.createElementNS(XML_NAMESPACE, "Reference");
            Element proofNode = doc.createElementNS(XML_NAMESPACE, "Proof");
            byte[] proof = output.getProof(selectorResults.get(pointer));
            proofNode.appendChild(doc.createTextNode(base64.encodeToString(proof)));

            reference.appendChild(pointer);
            reference.appendChild(proofNode);
            references.appendChild(reference);
        }

        Element tag = doc.createElementNS(XML_NAMESPACE, "Tag");
        tag.appendChild(doc.createTextNode(base64.encodeToString(output.getTag())));
        signatureValue.appendChild(tag);

        Element proofOfTag = doc.createElementNS(XML_NAMESPACE, "ProofOfTag");
        proofOfTag.appendChild(doc.createTextNode(base64.encodeToString(output.getProofOfTag())));
        signatureValue.appendChild(proofOfTag);

        Element accumulator = doc.createElementNS(XML_NAMESPACE, "Accumulator");
        accumulator.appendChild(doc.createTextNode(base64.encodeToString(output.getAccumulator())));
        signatureValue.appendChild(accumulator);

        signature.appendChild(references);
        signature.appendChild(signatureValue);
        root.appendChild(signature);
        return doc;
    }

    @Override
    public boolean engineVerify() throws RedactableXMLSignatureException {
        Base64.Decoder base64 = Base64.getDecoder();
        Node signatureNode = getSignatureNode(root, XML_NAMESPACE);

        // Enveloped signature; remove signature node from document, before doing any further processing
        root.removeChild(signatureNode);

        Node references = getFirstChildSafe(signatureNode, "References");
        Node signatureValue = getNextSiblingSafe(references, "SignatureValue");

        Node tagNode = getFirstChildSafe(signatureValue, "Tag");
        Node proofOfTagNode = getNextSiblingSafe(tagNode, "ProofOfTag");
        Node accumulatorNode = getNextSiblingSafe(proofOfTagNode, "Accumulator");

        byte[] tag = base64.decode(getText(tagNode));
        byte[] proofOfTag = base64.decode(getText(proofOfTagNode));
        byte[] accumulator = base64.decode(getText(accumulatorNode));

        PSSignatureOutput.Builder builder = new PSSignatureOutput.Builder(tag, proofOfTag, accumulator);

        NodeList referencesList = references.getChildNodes();
        for (int i = 0; i < referencesList.getLength(); i++) {
            Node node = checkNode(referencesList.item(i), "Reference");
            Node pointer = getFirstChildSafe(node, "Pointer");
            Node proofNode = getNextSiblingSafe(pointer, "Proof");
            String uri = getAttributeValue(pointer, "URI");
            byte[] part = canonicalize(dereference(uri, root));
            byte[] proof = base64.decode(getText(proofNode));
            try {
                builder.add(concat(pointer, part), proof);
            } catch (PSRSSException e) {
                throw new RedactableXMLSignatureException(e);
            }
        }

        // TODO Copy root and do processing on copy instead of deleting/adding the signature node
        root.appendChild(signatureNode);

        PSSignatureOutput signatureOutput = builder.build();
        try {
            return signature.verify(signatureOutput);
        } catch (RedactableSignatureException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public Document engineRedact() throws RedactableXMLSignatureException {
        Node references = checkNode(getSignatureNode(root, XML_NAMESPACE).getFirstChild(), "References");
        NodeList referencesList = references.getChildNodes();
        Set<Element> pointerElements = selectorResults.keySet();
        Set<String> selectors = new HashSet<>();
        List<Node> selectedNodes = new ArrayList<>(pointerElements.size());
        List<Node> referencesToRemove = new LinkedList<>();

        for (Element element : pointerElements) {
            String uri = element.getAttribute("URI");
            selectors.add(uri);
            selectedNodes.add(dereference(uri, root));
        }

        selectedNodes.sort(new Comparator<Node>() {
            @Override
            public int compare(Node node1, Node node2) {
                if (isDescendant(node1, node2)) {
                    return 1;
                }
                return -1;
            }
        });

        for (Node selectedNode : selectedNodes) {
            selectedNode.getParentNode().removeChild(selectedNode);
        }

        for (int i = 0; i < referencesList.getLength(); i++) {
            Node reference = checkNode(referencesList.item(i), "Reference");
            Node pointer = getFirstChildSafe(reference, "Pointer");
            String uri = getAttributeValue(pointer, "URI");
            if (selectors.contains(uri)) {
                // Don't remove the reference here, since that changes the referencesList and breaks the iteration.
                // Instead, save the reference and remove it later.
                referencesToRemove.add(reference);
            }
        }

        for (Node node : referencesToRemove) {
            node.getParentNode().removeChild(node);
        }

        return getOwnerDocument(root);
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
