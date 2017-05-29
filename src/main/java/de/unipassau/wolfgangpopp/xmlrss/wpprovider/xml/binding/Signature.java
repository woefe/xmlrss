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
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * The Signature class is responsible for marshalling and unmarshalling the <code>Signature</code> element of the
 * redactable signature XML encoding. The signature element is the root element of the XML encoding.
 *
 * The XSD Schema of the signature element is defined as following
 * <pre>
 * {@code
 * <element name="Signature">
 *     <complexType>
 *         <sequence>
 *             <element ref="drs:SignatureInfo"/>
 *             <element ref="drs:References"/>
 *             <element name="SignatureValue" type="anyType"/>
 *             <element name="KeyInfo" type="anyType" minOccurs="0" maxOccurs="1"/>
 *         </sequence>
 *     </complexType>
 * </element>
 * }
 * </pre>
 *
 * @author Wolfgang Popp
 */
public final class Signature<S extends SignatureValue, P extends Proof> extends BindingElement<Signature> {

    private final Class<P> proofClass;
    private final Class<S> signatureValueClass;
    private List<Reference<P>> references = new ArrayList<>();
    private S signatureValue;
    private SignatureInfo signatureInfo;

    public Signature(Class<P> proofClass, Class<S> signatureValueClass) {
        this.proofClass = proofClass;
        this.signatureValueClass = signatureValueClass;
    }

    public SignatureInfo getSignatureInfo() {
        return signatureInfo;
    }

    public List<Reference<P>> getReferences() {
        return references;
    }

    public S getSignatureValue() {
        return signatureValue;
    }

    public Signature setSignatureInfo(SignatureInfo signatureInfo) {
        this.signatureInfo = signatureInfo;
        return this;
    }

    public Signature addReference(Reference<P> reference) {
        references.add(reference);
        return this;
    }

    public Signature setSignatureValue(S signatureValue) {
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
    public Signature<S, P> unmarshall(Node node) throws RedactableXMLSignatureException {
        Node signature = checkThisNode(node);
        Node signatureInfo = signature.getFirstChild();
        this.signatureInfo = new SignatureInfo().unmarshall(signatureInfo);

        Node referencesNode = signatureInfo.getNextSibling();
        NodeList references = referencesNode.getChildNodes();
        this.references.clear();
        for (int i = 0; i < references.getLength(); i++) {
            this.references.add(new Reference<>(proofClass).unmarshall(references.item(i)));
        }

        Node signatureValue = referencesNode.getNextSibling();
        try {
            this.signatureValue = (S) signatureValueClass.newInstance().unmarshall(signatureValue);
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RedactableXMLSignatureException(signatureValueClass.getName() +
                    " has no public default constructor", e);
        }
        return this;
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
