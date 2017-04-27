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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
@XmlRootElement(name = "Signature")
@XmlType(propOrder = {"references", "signatureValue"})
public final class Signature<S extends SignatureValue, P extends Proof> {
    private final Class<? extends Proof> proofClass;
    private final Class<? extends SignatureValue> signatureValueClass;
    private List<Reference<P>> references = new LinkedList<>();
    private S signatureValue;

    private Signature() {
        this(null, null);
    }

    public Signature(Class<S> signatureValueClass, Class<P> proofClass) {
        this.proofClass = proofClass;
        this.signatureValueClass = signatureValueClass;
    }

    @XmlElementWrapper(name = "References")
    @XmlElement(name = "Reference")
    public List<Reference<P>> getReferences() {
        return references;
    }

    @XmlAnyElement(lax = true)
    public S getSignatureValue() {
        return signatureValue;
    }

    public Signature addReference(Reference<P> reference) {
        references.add(reference);
        return this;
    }

    public Signature setSignatureValue(S signatureValue) {
        this.signatureValue = signatureValue;
        return this;
    }

    public Document marshall(Document document) throws JAXBException {
        final JAXBContext context = JAXBContext.newInstance(this.getClass(), proofClass, signatureValueClass);
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

        m.marshal(this, document.getDocumentElement());
        return document;
    }

    public static <S extends SignatureValue, P extends Proof>
    Signature<S, P> unmarshall(Class<S> signatureValueClass, Class<P> proofClass, Node signatureNode) throws JAXBException {

        final JAXBContext context = JAXBContext.newInstance(Signature.class, proofClass, signatureValueClass);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        return (Signature<S, P>) unmarshaller.unmarshal(signatureNode);
    }
}
