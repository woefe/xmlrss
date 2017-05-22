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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author Wolfgang Popp
 */
public final class Reference extends BindingElement<Reference> {
    private Pointer pointer;
    private Proof proof;

    public Reference() {
    }

    public Reference(Pointer pointer, Proof proof) {
        this.pointer = pointer;
        this.proof = proof;
    }

    public Pointer getPointer() {
        return pointer;
    }

    public Proof getProof() {
        return proof;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Reference reference = (Reference) o;

        return (pointer != null ? pointer.equals(reference.pointer) : reference.pointer == null)
                && (proof != null ? proof.equals(reference.proof) : reference.proof == null);
    }

    @Override
    public int hashCode() {
        int result = pointer != null ? pointer.hashCode() : 0;
        result = 31 * result + (proof != null ? proof.hashCode() : 0);
        return result;
    }

    @Override
    public Reference unmarshall(Node node) {
        return null;
    }

    @Override
    public Node marshall(Document document) {
        Element reference = createThisElement(document);
        reference.appendChild(pointer.marshall(document));
        reference.appendChild(proof.marshall(document));
        return reference;
    }
}
