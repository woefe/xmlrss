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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.CanonicalizationException;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @author Wolfgang Popp
 */
public abstract class RedactableXMLSignatureSpi {

    private Canonicalizer canonicalizer;

    protected RedactableXMLSignatureSpi() throws RedactableXMLSignatureException {
        Init.init();
        try {
            canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
        } catch (InvalidCanonicalizerException e) {
            throw new RedactableXMLSignatureException(e);
        }

    }

    protected Node dereference(String uri, Node root) throws RedactableXMLSignatureException {
        return Dereferencer.dereference(uri, root);
    }

    protected byte[] canonicalize(Node node) throws RedactableXMLSignatureException {
        try {
            return canonicalizer.canonicalizeSubtree(node);
        } catch (CanonicalizationException e) {
            throw new RedactableXMLSignatureException("Cannot canonicalize the given node");
        }
    }

    protected Node getFirstChildSafe(Node parent, String expectedNodeName) throws RedactableXMLSignatureException {
        return checkNode(parent.getFirstChild(), expectedNodeName);
    }

    protected Node getNextSiblingSafe(Node sibling, String expectedNodeName) throws RedactableXMLSignatureException{
        return checkNode(sibling.getNextSibling(), expectedNodeName);
    }

    protected Node checkNode(Node node, String expectedNodeName) throws RedactableXMLSignatureException {
        if (node == null || !node.getNodeName().equals(expectedNodeName)) {
            throw new RedactableXMLSignatureException("Cannot find expected node " + expectedNodeName);
        }

        return node;
    }

    protected String getText(Node node) throws RedactableXMLSignatureException {
        Node textNode = node.getFirstChild();
        if (textNode.getNodeType() != Node.TEXT_NODE) {
            throw new RedactableXMLSignatureException("Cannot get text from node" + node.getNodeName());
        }

        return textNode.getNodeValue();
    }

    protected Document getOwnerDocument(Node node) {
        if(node.getNodeType() == Node.DOCUMENT_NODE){
            return (Document) node;
        }
        return node.getOwnerDocument();
    }

    public abstract void engineInitSign(KeyPair keyPair) throws InvalidKeyException;

    public abstract void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException;

    public abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    public abstract void engineInitRedact(PublicKey publicKey) throws InvalidKeyException;

    public abstract void engineAddPartSelector(String uri) throws RedactableXMLSignatureException;

    public abstract void engineSetRootNode(Node node);

    public abstract void engineSign() throws RedactableXMLSignatureException;

    public abstract boolean engineVerify() throws RedactableXMLSignatureException;

    public abstract void engineRedact() throws RedactableXMLSignatureException;
}
