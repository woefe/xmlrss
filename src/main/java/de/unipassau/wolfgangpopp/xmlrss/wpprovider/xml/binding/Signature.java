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

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public final class Signature extends BindingElement<Signature> {
    private List<Reference> references = new ArrayList<>();
    private SignatureValue signatureValue;
    private SignatureInfo signatureInfo;

    public Signature() {
    }

    public SignatureInfo getSignatureInfo() {
        return signatureInfo;
    }

    public List<Reference> getReferences() {
        return references;
    }

    public SignatureValue getSignatureValue() {
        return signatureValue;
    }

    public Signature setSignatureInfo(SignatureInfo signatureInfo) {
        this.signatureInfo = signatureInfo;
        return this;
    }

    public Signature addReference(Reference reference) {
        references.add(reference);
        return this;
    }

    public Signature setSignatureValue(SignatureValue signatureValue) {
        this.signatureValue = signatureValue;
        return this;
    }

    /*
    public Document marshall(Document document) throws JAXBException {
        final JAXBContext context = JAXBContext.newInstance(this.getClass(), proofClass, signatureValueClass);
        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

        m.marshal(this, document.getDocumentElement());
        return document;
    }

    /*
    public static Signature unmarshall(Node signatureNode) throws JAXBException {

        final JAXBContext context = JAXBContext.newInstance(Signature.class, proofClass, signatureValueClass);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        Signature<S, P> signature = (Signature<S, P>) unmarshaller.unmarshal(signatureNode);
        signature.proofClass = proofClass;
        signature.signatureValueClass = signatureValueClass;
        return signature;
    }
    */

    @Override
    public Signature unmarshall(Node node) {
        return null;
    }

    @Override
    public Node marshall(Document document) {
        Element element = createThisElement(document);
        element.appendChild(signatureInfo.marshall(document));
        Node references = element.appendChild(createElement(document, "References"));
        for (Reference reference : this.references) {
            references.appendChild(reference.marshall(document));
        }

        element.appendChild(references);
        element.appendChild(signatureValue.marshall(document));
        element.setAttribute("xmlns", RedactableXMLSignature.XML_NAMESPACE);
        return element;
    }
}
