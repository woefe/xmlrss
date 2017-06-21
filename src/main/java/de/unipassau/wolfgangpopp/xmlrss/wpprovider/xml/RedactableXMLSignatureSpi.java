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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Pointer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Signature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.SignatureValue;
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
 * This class defines the Service Provider Interface for the {@link RedactableXMLSignature} class.
 * <p>
 * All abstract methods in this class must be implemented by cryptographic services providers who wish to supply the
 * implementation of a particular redactable xml signature algorithm.
 * <p>
 * Alternatively, implementors can also choose to extend the {@link AbstractRedactableXMLSignature}, which
 * already implements many engine methods defined by this class. This reduces the necessary work for implementing the
 * XML encoding to implementatinos of {@link de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding.Proof} and
 * {@link SignatureValue} and the corresponding marshalling and unmarshalling routines.
 * <p>
 * Implementations extending this class directly can take advantage of the classes in the
 * <code>de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding</code> package. The {@link Signature} class provides
 * more documentation on the redactable XML signature encoding.
 *
 * @author Wolfgang Popp
 */
public abstract class RedactableXMLSignatureSpi {

    /**
     * Checks whether the given ancestor has the given child.
     *
     * @param ancestor the ancestor
     * @param child    the child
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

    /**
     * Removes the nodes identified by the given uris from the document.
     *
     * @param root the root node of the document
     * @param uris the URIs of elements to remove
     * @throws RedactableXMLSignatureException if the URIs cannot be dereferenced and removed
     */
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

    /**
     * Initializes this redactable XML signature engine for signing.
     *
     * @param keyPair the keypair of the identity whose signature will be generated
     * @throws InvalidKeyException if the key is cannot be used by the underlying redactable signature algorithm
     */
    public void engineInitSign(KeyPair keyPair) throws InvalidKeyException {
        engineInitSign(keyPair, new SecureRandom());
    }

    /**
     * Initializes this redactable xml signature engine for signing with the specified source of randomness and key
     * pair.
     *
     * @param keyPair the keypair of the identity whose signature will be generated
     * @param random  the source of randomness
     * @throws InvalidKeyException if the key is cannot be used by the underlying redactable signature algorithm
     */
    public abstract void engineInitSign(KeyPair keyPair, SecureRandom random) throws InvalidKeyException;

    /**
     * Initializes this redactable XML signature engine for verification.
     *
     * @param publicKey the public key of the identity whose signature is going to be verified
     * @throws InvalidKeyException if the key is cannot be used by the underlying redactable signature algorithm
     */
    public abstract void engineInitVerify(PublicKey publicKey) throws InvalidKeyException;

    /**
     * Initializes this redactable XML signature engine for redaction.
     *
     * @param publicKey the public key of the identity whose signature is going to be redacted
     * @throws InvalidKeyException if the key is cannot be used by the underlying redactable signature algorithm
     */
    public abstract void engineInitRedact(PublicKey publicKey) throws InvalidKeyException;

    /**
     * Adds an URI for signing.
     * <p>
     * This URI is dereferenced and a {@link Pointer} element is built from it, which is concatenated with the
     * dreferenced content
     *
     * @param uri          the URI to add (and dereference)
     * @param isRedactable indicates whether the added URI is redactable
     * @throws RedactableXMLSignatureException if the URI is not well formed or cannot be dereferenced
     */
    public abstract void engineAddSignSelector(String uri, boolean isRedactable) throws RedactableXMLSignatureException;

    /**
     * Adds an URI for redaction.
     *
     * @param uri the URI that identifies the element in the document and in the <code>Signature</code> element.
     * @throws RedactableXMLSignatureException if the URI is not well formed or cannot be dereferenced
     */
    public abstract void engineAddRedactSelector(String uri) throws RedactableXMLSignatureException;

    /**
     * Sets the root node of the document.
     *
     * @param root the root node of the document that is signed, verified, or redacted
     */
    public abstract void engineSetRootNode(Node root);

    /**
     * Signs the selected elements of the previously added document root.
     * <p>
     * This method creates the <code>Signature</code> element and adds it to the document as the last child of the root
     * node. This method does not create a new document, but modifies the previously loaded document.
     *
     * @return the modified document that now has the <code>Signature</code> element embedded.
     * @throws RedactableXMLSignatureException if the underlying redactable signature scheme cannot process the given
     *                                         elements or if URIs cannot be dereferenced
     */
    public abstract Document engineSign() throws RedactableXMLSignatureException;

    /**
     * Verifies the previously added document.
     * <p>
     * The document must have a <code>Signature</code> element that is compliant to the schema for redactable XML
     * signatures. Since this element is embedded within the document, the document is "self-contained" and no URIs
     * have to be added for verification.
     *
     * @return true if the <code>Signature</code> element within the document is a valid signature for the document
     * @throws RedactableXMLSignatureException if the document does not have a <code>Signature</code> element or is
     *                                         missing some elements or if the underlying scheme throws an exception
     */
    public abstract boolean engineVerify() throws RedactableXMLSignatureException;

    /**
     * Redacts the selected elements from the previously added document root.
     * <p>
     * This method does not create a new document, but modifies the previously loaded document.
     *
     * @return the redacted document with the modified <code>Signature</code> element
     * @throws RedactableXMLSignatureException if the underlying redactable signature scheme cannot process the given
     *                                         elements or if URIs cannot be dereferenced
     */
    public abstract Document engineRedact() throws RedactableXMLSignatureException;
}
