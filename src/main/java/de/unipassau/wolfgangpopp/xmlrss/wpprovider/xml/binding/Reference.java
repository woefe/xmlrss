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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * The Reference class is responsible for marshalling and unmarshalling the <code>Reference</code> element of the
 * redactable signature XML encoding. References contain proof elements which have to be implemented differently for
 * various redactable signature schemes. The type parameter <code>P</code> denotes the specific {@link Proof} class.
 * <p>
 * The XSD Schema of the reference is defined as following
 * <pre>
 * {@code
 * <element name="Reference">
 *     <complexType>
 *         <sequence>
 *             <element ref="drs:Pointer"/>
 *             <element name="Proof" type="anyType"/>
 *         </sequence>
 *     </complexType>
 * </element>
 * }
 * </pre>
 *
 * @author Wolfgang Popp
 */
public final class Reference<P extends Proof> extends BindingElement<Reference> {
    private Pointer pointer;
    private P proof;
    private Class<P> proofClass;

    /**
     * Constructs a new empty reference.
     * <p>
     * The reference is initialized when the unmarshall method is called.
     *
     * @param proofClass the class of the proof used in the redactable XML signature encoding
     */
    public Reference(Class<P> proofClass) {
        this.proofClass = proofClass;
    }

    /**
     * Constructs a new reference with the given pointer and proof.
     *
     * @param pointer    the pointer of this reference
     * @param proof      the proof of this reference
     * @param proofClass the class of the used proof
     */
    public Reference(Pointer pointer, P proof, Class<P> proofClass) {
        this.pointer = pointer;
        this.proof = proof;
        this.proofClass = proofClass;
    }

    /**
     * Returns the pointer of this reference.
     *
     * @return the pointer of this reference
     */
    public Pointer getPointer() {
        return pointer;
    }

    /**
     * Returns the proof of this reference.
     *
     * @return the proof of this reference
     */
    public P getProof() {
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

    @SuppressWarnings("unchecked")
    @Override
    public Reference<P> unmarshall(Node node) throws RedactableXMLSignatureException {
        Node reference = checkThisNode(node);
        Node pointer = reference.getFirstChild();
        this.pointer = new Pointer().unmarshall(pointer);

        Node proof = pointer.getNextSibling();
        try {
            this.proof = (P) proofClass.newInstance().unmarshall(proof);
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RedactableXMLSignatureException(e);
        }
        return this;
    }

    @Override
    public Node marshall(Document document) {
        Element reference = createThisElement(document);
        reference.appendChild(pointer.marshall(document));
        reference.appendChild(proof.marshall(document));
        return reference;
    }
}
