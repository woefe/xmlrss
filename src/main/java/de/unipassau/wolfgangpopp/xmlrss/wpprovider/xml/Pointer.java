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

import com.sun.org.apache.xml.internal.security.c14n.CanonicalizationException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import org.w3c.dom.Node;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

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

    private final byte[] concatDereference;

    private Pointer() throws RedactableXMLSignatureException {
        this(null, null);
    }

    public Pointer(Node root, String uri) throws RedactableXMLSignatureException {
        this(root, uri, true);
    }

    public Pointer(Node root, String uri, boolean isRedactable) throws RedactableXMLSignatureException {
        this(root, uri, isRedactable, null);

    }

    public Pointer(Node root, String uri, boolean isRedactable, String id) throws RedactableXMLSignatureException {
        this.uri = uri;
        this.isRedactable = isRedactable;
        this.id = id;
        concatDereference = concatDereference(root);
    }

    private byte[] concatDereference(Node root) throws RedactableXMLSignatureException {
        byte[] c14n;
        Node dereference = Dereferencer.dereference(uri, root);
        try {
            c14n = Canonicalizer.canonicalize(dereference);
        } catch (CanonicalizationException e) {
            throw new RedactableXMLSignatureException(e);
        }

        return new ByteArray(c14n).concat(marshall()).getArray();
    }

    private byte[] marshall() {
        StringBuilder sb = new StringBuilder();
        sb.append("<Pointer ");
        sb.append("URI=\"").append(uri).append('"');

        if (isRedactable != null) {
            sb.append(" Redactable=\"").append(isRedactable).append('"');
        }

        if (id != null) {
            sb.append(" id=\"").append(id).append('"');
        }

        return sb.append("/>").toString().getBytes();
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

    public byte[] getConcatDereference() {
        return concatDereference;
    }
}
