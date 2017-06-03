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

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * @author Wolfgang Popp
 */
public abstract class RedactableXMLSignatureSpi {

    /**
     * Checks whether the given ancestor has the given child.
     *
     * @param ancestor
     * @param child
     * @return true if <code>child</code> is a descendant of <code>ancestor</code> or if
     * <code>child.equals(ancestor)</code>, false otherwise
     */
    protected boolean isDescendant(Node ancestor, Node child) {
        if (ancestor.equals(child)) {
            return true;
        }

        NodeList childNodes = ancestor.getChildNodes();
        boolean isChild = false;

        for (int i = 0; i < childNodes.getLength(); i++) {
            isChild = isChild || isDescendant(childNodes.item(i), child);
        }
        return isChild;
    }

    protected void removeNodes(Node root, Set<String> uris) throws RedactableXMLSignatureException {
        List<Node> selectedNodes = new ArrayList<>(uris.size());

        for (String uri : uris) {
            selectedNodes.add(Dereferencer.dereference(uri, root));
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
    }

    public void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
        engineInitSign(keyPair, new SecureRandom());
    }

    public abstract void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException;

    public abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    public abstract void engineInitRedact(PublicKey publicKey) throws InvalidKeyException;

    public abstract void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException;

    public abstract void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException;

    public abstract void engineSetRootNode(Node root);

    public abstract Document engineSign() throws RedactableXMLSignatureException;

    public abstract boolean engineVerify() throws RedactableXMLSignatureException;

    public abstract Document engineRedact() throws RedactableXMLSignatureException;
}
