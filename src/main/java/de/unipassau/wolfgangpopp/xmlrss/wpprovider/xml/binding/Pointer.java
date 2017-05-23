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
 * @author Wolfgang Popp
 */
public final class Pointer extends BindingElement<Pointer> {
    private String uri;
    private Boolean isRedactable;
    private String id;

    private byte[] concatDereference;

    public Pointer() {
        this(null, null, null);
    }

    public Pointer(String uri) {
        this(uri, null, null);
    }

    public Pointer(String uri, Boolean isRedactable) {
        this(uri, isRedactable, null);
    }

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
        this.concatDereference = concatNode(dereference, root);
        return this;
    }

    public byte[] concatNode(Node node, Node root) throws RedactableXMLSignatureException {
        byte[] c14nNode;
        try {
            c14nNode = Canonicalizer.canonicalize(node);
        } catch (CanonicalizationException e) {
            throw new RedactableXMLSignatureException(e);
        }

        try {
            byte[] c14nPointer = Canonicalizer.canonicalize(marshall(getOwnerDocument(root)));
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

    public byte[] concatDereference(Node root) throws RedactableXMLSignatureException {
        return initConcatDereference(root).concatDereference;
    }

    public String getUri() {
        return uri;
    }

    public Boolean isRedactable() {
        return isRedactable == null || isRedactable;
    }

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
