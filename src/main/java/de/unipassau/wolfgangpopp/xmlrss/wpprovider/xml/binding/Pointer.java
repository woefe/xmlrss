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

import com.sun.org.apache.xml.internal.security.c14n.CanonicalizationException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Canonicalizer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.Dereferencer;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBException;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.createNode;
import static de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.XMLUtils.getOwnerDocument;

/**
 * @author Wolfgang Popp
 */
@XmlRootElement(name = "Pointer")
@XmlType(propOrder = {"uri", "isRedactable", "id"})
public final class Pointer {
    @XmlAttribute(name = "URI", required = true)
    private String uri;

    @XmlAttribute(name = "Redactable")
    private Boolean isRedactable;

    @XmlAttribute(name = "id")
    private String id;

    private byte[] concatDereference;

    private Pointer() throws RedactableXMLSignatureException {
        this(null);
    }

    public Pointer(String uri) throws RedactableXMLSignatureException {
        this(uri, null);
    }

    public Pointer(String uri, Boolean isRedactable) throws RedactableXMLSignatureException {
        this(uri, isRedactable, null);
    }

    public Pointer(String uri, Boolean isRedactable, String id) throws RedactableXMLSignatureException {
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
        byte[] c14n;
        try {
            c14n = Canonicalizer.canonicalize(node);
        } catch (CanonicalizationException e) {
            throw new RedactableXMLSignatureException(e);
        }

        try {
            return new ByteArray(c14n).concat(marshall(root)).getArray();
        } catch (CanonicalizationException | JAXBException e) {
            throw new RedactableXMLSignatureException(e);
        }
    }

    private byte[] marshall(Node root) throws CanonicalizationException, JAXBException {
        Node node = createNode(getOwnerDocument(root), this, getClass(), "Pointer");
        return Canonicalizer.canonicalize(node);
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
}
