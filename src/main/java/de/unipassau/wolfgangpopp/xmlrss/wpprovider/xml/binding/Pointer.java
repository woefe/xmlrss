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

package de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.binding;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Canonicalizer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Dereferencer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.getOwnerDocument;

/**
 * The Pointer class is responsible for marshalling and unmarshalling the <code>Pointer</code> element of the redactable
 * signature XML encoding. The XSD Schema of the pointer is defined as following
 * <pre>
 * {@code <element name="Pointer">
 *     <complexType>
 *         <attribute name="Id" type="ID" use="optional"/>
 *         <attribute name="URI" type="anyURI" use="required"/>
 *         <attribute name="Redactable" type="boolean" use="optional"/>
 *     </complexType>
 * </element>
 * }
 * </pre>
 * <p>
 * The Pointer element is concatenated with the content it points to during generation of the redactable XML signature.
 *
 * @author Wolfgang Popp
 */
public final class Pointer extends BindingElement<Pointer> {

    private String uri;
    private Boolean isRedactable;
    private String id;
    private byte[] concatDereference;

    /**
     * Constructs a new pointer where all attributes are set to null.
     */
    public Pointer() {
        this(null, null, null);
    }

    /**
     * Constructs a new pointer from the given URI.
     *
     * @param uri the URI the pointer points to
     */
    public Pointer(String uri) {
        this(uri, null, null);
    }

    /**
     * Constructs a new pointer from the given URI  that is redactable if the given boolean parameter is true.
     *
     * @param uri          the URI the pointer points to
     * @param isRedactable indicates whether this pointer is redactable
     */
    public Pointer(String uri, Boolean isRedactable) {
        this(uri, isRedactable, null);
    }

    /**
     * Constructs a new pointer with the given ID and URI that is redactable if the given boolean parameter is true.
     *
     * @param uri          the URI the pointer points to
     * @param isRedactable indicates whether this pointer is redactable
     * @param id           the id of this pointer
     */
    public Pointer(String uri, Boolean isRedactable, String id) {
        this.uri = uri;
        this.isRedactable = isRedactable;
        this.id = id;
    }

    private Pointer initConcatDereference(Node root) throws RedactableXMLSignatureException {
        if (concatDereference != null) {
            return this;
        }

        Node dereference = Dereferencer.dereference(uri, root);
        this.concatDereference = concatNode(dereference);
        return this;
    }

    /**
     * Concatenates this pointer with the given node.
     * <p>
     * The node and this pointer are first canonicalized before concatenation.
     *
     * @param node the node concatenated to this pointer
     * @return the concatenation of this pointer and the given node
     * @throws RedactableXMLSignatureException if canonicalization fails
     */
    public byte[] concatNode(Node node) throws RedactableXMLSignatureException {
        byte[] c14nNode;
        try {
            c14nNode = Canonicalizer.canonicalize(node);
        } catch (CanonicalizationException e) {
            throw new RedactableXMLSignatureException(e);
        }

        try {
            byte[] c14nPointer = Canonicalizer.canonicalize(marshall(getOwnerDocument(node)));
            return new ByteArray(c14nNode).concat(c14nPointer).getArray();
        } catch (CanonicalizationException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Pointer pointer = (Pointer) o;

        return uri.equals(pointer.uri);
    }

    @Override
    public int hashCode() {
        return uri.hashCode();
    }

    /**
     * Concatenates this pointer with the content it points to.
     *
     * @param root the root node used for dereferencing this pointer
     * @return the concatenation of this pointer and its dereferenced content
     * @throws RedactableXMLSignatureException if dereferenciation or canonicalization failed
     */
    public byte[] concatDereference(Node root) throws RedactableXMLSignatureException {
        return initConcatDereference(root).concatDereference;
    }

    /**
     * Returns the URI of this pointer.
     *
     * @return the URI of this pointer
     */
    public String getUri() {
        return uri;
    }

    /**
     * Checks if this pointer is redactable.
     *
     * @return true if this pointer is redactable. null or false otherwise
     */
    public Boolean isRedactable() {
        return isRedactable == null || isRedactable;
    }

    /**
     * Returns the id of this pointer.
     *
     * @return the id of this pointer or null if no ID is specified
     */
    public String getId() {
        return id;
    }

    @Override
    public Pointer unmarshall(Node node) throws RedactableXMLSignatureException {
        Node pointer = checkThisNode(node);
        NamedNodeMap attributes = pointer.getAttributes();

        Node id = attributes.getNamedItem("Id");
        if (id != null) {
            this.id = id.getTextContent();
        }

        Node uri = attributes.getNamedItem("URI");
        if (uri != null) {
            this.uri = uri.getTextContent();
        }

        Node isRedactable = attributes.getNamedItem("Redactable");
        if (isRedactable != null) {
            this.isRedactable = Boolean.valueOf(isRedactable.getTextContent());
        }
        return this;
    }

    @Override
    public Node marshall(Document document) {
        Element pointer = createThisElement(document);
        if (id != null) {
            pointer.setAttribute("Id", id);
        }
        if (uri == null) {
            throw new IllegalStateException("URI cannot be null");
        }
        pointer.setAttribute("URI", uri);
        if (isRedactable != null) {
            pointer.setAttribute("Redactable", isRedactable.toString());
        }
        return pointer;
    }
}
