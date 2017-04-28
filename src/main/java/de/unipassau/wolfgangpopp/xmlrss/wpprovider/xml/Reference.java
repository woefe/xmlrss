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

import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Wolfgang Popp
 */
@XmlRootElement(name = "Reference")
@XmlType(propOrder = {"pointer", "proof"})
public final class Reference<P extends Proof> {
    @XmlElement(name = "Pointer")
    private Pointer pointer;

    @XmlAnyElement(lax = true)
    private P proof;

    private Reference() {
    }

    public Reference(Pointer pointer, P proof) {
        this.pointer = pointer;
        this.proof = proof;
    }

    public Pointer getPointer() {
        return pointer;
    }

    public P getProof() {
        return proof;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Reference<?> reference = (Reference<?>) o;

        if (pointer != null ? !pointer.equals(reference.pointer) : reference.pointer != null) return false;
        return proof != null ? proof.equals(reference.proof) : reference.proof == null;
    }

    @Override
    public int hashCode() {
        int result = pointer != null ? pointer.hashCode() : 0;
        result = 31 * result + (proof != null ? proof.hashCode() : 0);
        return result;
    }
}
